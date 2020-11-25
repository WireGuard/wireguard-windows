/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
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

func printPanic() {
	if x := recover(); x != nil {
		for _, line := range append([]string{fmt.Sprint(x)}, strings.Split(string(debug.Stack()), "\n")...) {
			if len(strings.TrimSpace(line)) > 0 {
				log.Println(line)
			}
		}
		panic(x)
	}
}

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

	err = ringlogger.InitGlobalLogger("MGR")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}
	defer printPanic()

	log.Println("Starting", version.UserAgent())

	path, err := os.Executable()
	if err != nil {
		serviceError = services.ErrorDetermineExecutablePath
		return
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		serviceError = services.ErrorOpenNULFile
		return
	}

	err = trackExistingTunnels()
	if err != nil {
		serviceError = services.ErrorTrackTunnels
		return
	}

	conf.RegisterStoreChangeCallback(func() { conf.MigrateUnencryptedConfigs(3) })
	conf.RegisterStoreChangeCallback(IPCServerNotifyTunnelsChange)

	procs := make(map[uint32]*os.Process)
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

			// TODO: we lock the OS thread so that these inheritable handles don't escape into other processes that
			// might be running in parallel Go routines. But the Go runtime is strange and who knows what's really
			// happening with these or what is inherited. We need to do some analysis to be certain of what's going on.
			runtime.LockOSThread()
			ourReader, theirReader, theirReaderStr, ourWriter, theirWriter, theirWriterStr, err := inheritableSocketpairEmulation()
			if err != nil {
				log.Printf("Unable to create two inheritable RPC pipes: %v", err)
				return
			}
			ourEvents, theirEvents, theirEventStr, err := inheritableEvents()
			if err != nil {
				log.Printf("Unable to create one inheritable events pipe: %v", err)
				return
			}
			IPCServerListen(ourReader, ourWriter, ourEvents, elevatedToken)
			theirLogMapping, theirLogMappingHandle, err := ringlogger.Global.ExportInheritableMappingHandleStr()
			if err != nil {
				log.Printf("Unable to export inheritable mapping handle for logging: %v", err)
				return
			}

			log.Printf("Starting UI process for user ‘%s@%s’ for session %d", username, domain, session)
			attr := &os.ProcAttr{
				Sys: &syscall.SysProcAttr{
					Token: syscall.Token(runToken),
				},
				Files: []*os.File{devNull, devNull, devNull},
				Dir:   userProfileDirectory,
			}
			procsLock.Lock()
			var proc *os.Process
			if alive := aliveSessions[session]; alive {
				proc, err = os.StartProcess(path, []string{path, "/ui", theirReaderStr, theirWriterStr, theirEventStr, theirLogMapping}, attr)
			} else {
				err = errors.New("Session has logged out")
			}
			procsLock.Unlock()
			theirReader.Close()
			theirWriter.Close()
			theirEvents.Close()
			windows.Close(theirLogMappingHandle)
			runtime.UnlockOSThread()
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
			processStatus, err := proc.Wait()
			if err == nil {
				exitCode := processStatus.Sys().(syscall.WaitStatus).ExitCode
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
			defer printPanic()
			startProcess(session)
			procsGroup.Done()
		}()
	}

	time.AfterFunc(time.Second*10, cleanupStaleWintunInterfaces)
	go checkForUpdates()

	var sessionsPointer *windows.WTS_SESSION_INFO
	var count uint32
	err = windows.WTSEnumerateSessions(0, 0, 1, &sessionsPointer, &count)
	if err != nil {
		serviceError = services.ErrorEnumerateSessions
		return
	}
	sessions := *(*[]windows.WTS_SESSION_INFO)(unsafe.Pointer(&struct {
		addr *windows.WTS_SESSION_INFO
		len  int
		cap  int
	}{sessionsPointer, int(count), int(count)}))
	for _, session := range sessions {
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
