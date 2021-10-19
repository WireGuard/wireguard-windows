/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"errors"
	"log"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/version"
)

type managerService struct{}

func (service *managerService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var err error
	serviceError := services.ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = services.DetermineErrorCode(err, serviceError)
		logErr := services.CombineErrors(err, serviceError)
		if logErr != nil {
			log.Print(logErr)
		}
		changes <- svc.Status{State: svc.StopPending}
	}()

	var logFile string
	logFile, err = conf.LogFile(true)
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}
	err = ringlogger.InitGlobalLogger(logFile, "MGR")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}

	log.Println("Starting", version.UserAgent())

	checkForPitfalls()

	path, err := os.Executable()
	if err != nil {
		serviceError = services.ErrorDetermineExecutablePath
		return
	}

	err = watchNewTunnelServices()
	if err != nil {
		serviceError = services.ErrorTrackTunnels
		return
	}

	conf.RegisterStoreChangeCallback(func() { conf.MigrateUnencryptedConfigs(changeTunnelServiceConfigFilePath) })
	conf.RegisterStoreChangeCallback(IPCServerNotifyTunnelsChange)

	procs := make(map[uint32]*uiProcess)
	aliveSessions := make(map[uint32]bool)
	procsLock := sync.Mutex{}
	stoppingManager := false
	operatorGroupSid, _ := windows.CreateWellKnownSid(windows.WinBuiltinNetworkConfigurationOperatorsSid)

	startProcess := func(session uint32) {
		defer func() {
			runtime.UnlockOSThread()
			procsLock.Lock()
			delete(aliveSessions, session)
			procsLock.Unlock()
		}()

		var userToken windows.Token
		err := windows.WTSQueryUserToken(session, &userToken)
		if err != nil {
			return
		}
		isAdmin := elevate.TokenIsElevatedOrElevatable(userToken)
		isOperator := false
		if !isAdmin && conf.AdminBool("LimitedOperatorUI") && operatorGroupSid != nil {
			linkedToken, err := userToken.GetLinkedToken()
			var impersonationToken windows.Token
			if err == nil {
				err = windows.DuplicateTokenEx(linkedToken, windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonationToken)
				linkedToken.Close()
			} else {
				err = windows.DuplicateTokenEx(userToken, windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonationToken)
			}
			if err == nil {
				isOperator, err = impersonationToken.IsMember(operatorGroupSid)
				isOperator = isOperator && err == nil
				impersonationToken.Close()
			}
		}
		if !isAdmin && !isOperator {
			userToken.Close()
			return
		}
		user, err := userToken.GetTokenUser()
		if err != nil {
			log.Printf("Unable to lookup user from token: %v", err)
			userToken.Close()
			return
		}
		username, domain, accType, err := user.User.Sid.LookupAccount("")
		if err != nil {
			log.Printf("Unable to lookup username from sid: %v", err)
			userToken.Close()
			return
		}
		if accType != windows.SidTypeUser {
			userToken.Close()
			return
		}
		userProfileDirectory, _ := userToken.GetUserProfileDirectory()
		var elevatedToken, runToken windows.Token
		if isAdmin {
			if userToken.IsElevated() {
				elevatedToken = userToken
			} else {
				elevatedToken, err = userToken.GetLinkedToken()
				userToken.Close()
				if err != nil {
					log.Printf("Unable to elevate token: %v", err)
					return
				}
				if !elevatedToken.IsElevated() {
					elevatedToken.Close()
					log.Println("Linked token is not elevated")
					return
				}
			}
			runToken = elevatedToken
		} else {
			runToken = userToken
		}
		defer runToken.Close()
		userToken = 0
		first := true
		for {
			if stoppingManager {
				return
			}

			procsLock.Lock()
			if alive := aliveSessions[session]; !alive {
				procsLock.Unlock()
				return
			}
			procsLock.Unlock()

			if !first {
				time.Sleep(time.Second)
			} else {
				first = false
			}

			ourReader, theirWriter, err := os.Pipe()
			if err != nil {
				log.Printf("Unable to create pipe: %v", err)
				return
			}
			theirReader, ourWriter, err := os.Pipe()
			if err != nil {
				log.Printf("Unable to create pipe: %v", err)
				return
			}
			theirEvents, ourEvents, err := os.Pipe()
			if err != nil {
				log.Printf("Unable to create pipe: %v", err)
				return
			}
			IPCServerListen(ourReader, ourWriter, ourEvents, elevatedToken)
			theirLogMapping, err := ringlogger.Global.ExportInheritableMappingHandle()
			if err != nil {
				log.Printf("Unable to export inheritable mapping handle for logging: %v", err)
				return
			}

			log.Printf("Starting UI process for user ‘%s@%s’ for session %d", username, domain, session)
			procsLock.Lock()
			var proc *uiProcess
			if alive := aliveSessions[session]; alive {
				proc, err = launchUIProcess(path, []string{
					path,
					"/ui",
					strconv.FormatUint(uint64(theirReader.Fd()), 10),
					strconv.FormatUint(uint64(theirWriter.Fd()), 10),
					strconv.FormatUint(uint64(theirEvents.Fd()), 10),
					strconv.FormatUint(uint64(theirLogMapping), 10),
				}, userProfileDirectory, []windows.Handle{
					windows.Handle(theirReader.Fd()),
					windows.Handle(theirWriter.Fd()),
					windows.Handle(theirEvents.Fd()),
					theirLogMapping}, runToken)
			} else {
				err = errors.New("Session has logged out")
			}
			procsLock.Unlock()
			theirReader.Close()
			theirWriter.Close()
			theirEvents.Close()
			windows.CloseHandle(theirLogMapping)
			if err != nil {
				ourReader.Close()
				ourWriter.Close()
				ourEvents.Close()
				log.Printf("Unable to start manager UI process for user '%s@%s' for session %d: %v", username, domain, session, err)
				return
			}

			procsLock.Lock()
			procs[session] = proc
			procsLock.Unlock()

			sessionIsDead := false
			if exitCode, err := proc.Wait(); err == nil {
				log.Printf("Exited UI process for user '%s@%s' for session %d with status %x", username, domain, session, exitCode)
				const STATUS_DLL_INIT_FAILED_LOGOFF = 0xC000026B
				sessionIsDead = exitCode == STATUS_DLL_INIT_FAILED_LOGOFF
			} else {
				log.Printf("Unable to wait for UI process for user '%s@%s' for session %d: %v", username, domain, session, err)
			}

			procsLock.Lock()
			delete(procs, session)
			procsLock.Unlock()
			ourReader.Close()
			ourWriter.Close()
			ourEvents.Close()

			if sessionIsDead {
				return
			}
		}
	}
	procsGroup := sync.WaitGroup{}
	goStartProcess := func(session uint32) {
		procsGroup.Add(1)
		go func() {
			startProcess(session)
			procsGroup.Done()
		}()
	}

	go checkForUpdates()

	var sessionsPointer *windows.WTS_SESSION_INFO
	var count uint32
	err = windows.WTSEnumerateSessions(0, 0, 1, &sessionsPointer, &count)
	if err != nil {
		serviceError = services.ErrorEnumerateSessions
		return
	}
	for _, session := range unsafe.Slice(sessionsPointer, count) {
		if session.State != windows.WTSActive && session.State != windows.WTSDisconnected {
			continue
		}
		procsLock.Lock()
		if alive := aliveSessions[session.SessionID]; !alive {
			aliveSessions[session.SessionID] = true
			if _, ok := procs[session.SessionID]; !ok {
				goStartProcess(session.SessionID)
			}
		}
		procsLock.Unlock()
	}
	windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessionsPointer)))

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptSessionChange}

	uninstall := false
loop:
	for {
		select {
		case <-quitManagersChan:
			uninstall = true
			break loop
		case c := <-r:
			switch c.Cmd {
			case svc.Stop:
				break loop
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.SessionChange:
				if c.EventType != windows.WTS_SESSION_LOGON && c.EventType != windows.WTS_SESSION_LOGOFF {
					continue
				}
				sessionNotification := (*windows.WTSSESSION_NOTIFICATION)(unsafe.Pointer(c.EventData))
				if uintptr(sessionNotification.Size) != unsafe.Sizeof(*sessionNotification) {
					log.Printf("Unexpected size of WTSSESSION_NOTIFICATION: %d", sessionNotification.Size)
					continue
				}
				if c.EventType == windows.WTS_SESSION_LOGOFF {
					procsLock.Lock()
					delete(aliveSessions, sessionNotification.SessionID)
					if proc, ok := procs[sessionNotification.SessionID]; ok {
						proc.Kill()
					}
					procsLock.Unlock()
				} else if c.EventType == windows.WTS_SESSION_LOGON {
					procsLock.Lock()
					if alive := aliveSessions[sessionNotification.SessionID]; !alive {
						aliveSessions[sessionNotification.SessionID] = true
						if _, ok := procs[sessionNotification.SessionID]; !ok {
							goStartProcess(sessionNotification.SessionID)
						}
					}
					procsLock.Unlock()
				}

			default:
				log.Printf("Unexpected service control request #%d", c)
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	procsLock.Lock()
	stoppingManager = true
	IPCServerNotifyManagerStopping()
	for _, proc := range procs {
		proc.Kill()
	}
	procsLock.Unlock()
	procsGroup.Wait()
	if uninstall {
		err = UninstallManager()
		if err != nil {
			log.Printf("Unable to uninstall manager when quitting: %v", err)
		}
	}
	return
}

func Run() error {
	return svc.Run("WireGuardManager", &managerService{})
}
