/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"errors"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
)

type managerService struct{}

func (service *managerService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var err error
	serviceError := ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = determineErrorCode(err, serviceError)
		logErr := combineErrors(err, serviceError)
		if logErr != nil {
			log.Print(logErr)
		}
		changes <- svc.Status{State: svc.StopPending}
	}()

	err = ringlogger.InitGlobalLogger("MGR")
	if err != nil {
		serviceError = ErrorRingloggerOpen
		return
	}
	defer func() {
		if x := recover(); x != nil {
			log.Printf("%v:\n%s", x, string(debug.Stack()))
			panic(x)
		}
	}()

	path, err := os.Executable()
	if err != nil {
		serviceError = ErrorDetermineExecutablePath
		return
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		serviceError = ErrorOpenNULFile
		return
	}

	err = trackExistingTunnels()
	if err != nil {
		serviceError = ErrorTrackTunnels
		return
	}

	conf.RegisterStoreChangeCallback(func() { conf.MigrateUnencryptedConfigs() }) // Ignore return value for now, but could be useful later.
	conf.RegisterStoreChangeCallback(IPCServerNotifyTunnelsChange)

	procs := make(map[uint32]*os.Process)
	aliveSessions := make(map[uint32]bool)
	procsLock := sync.Mutex{}
	var startProcess func(session uint32)
	stoppingManager := false

	startProcess = func(session uint32) {
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
		if !TokenIsMemberOfBuiltInAdministrator(userToken) {
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
		var elevatedToken windows.Token
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
		defer elevatedToken.Close()
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

			//TODO: we lock the OS thread so that these inheritable handles don't escape into other processes that
			// might be running in parallel Go routines. But the Go runtime is strange and who knows what's really
			// happening with these or what is inherited. We need to do some analysis to be certain of what's going on.
			runtime.LockOSThread()
			ourReader, theirReader, theirReaderStr, ourWriter, theirWriter, theirWriterStr, err := inheritableSocketpairEmulation()
			if err != nil {
				log.Printf("Unable to create two inheritable pipes: %v", err)
				return
			}
			ourEvents, theirEvents, theirEventStr, err := inheritableEvents()
			err = IPCServerListen(ourReader, ourWriter, ourEvents, elevatedToken)
			if err != nil {
				log.Printf("Unable to listen on IPC pipes: %v", err)
				return
			}
			theirLogMapping, theirLogMappingHandle, err := ringlogger.Global.ExportInheritableMappingHandleStr()
			if err != nil {
				log.Printf("Unable to export inheritable mapping handle for logging: %v", err)
				return
			}

			log.Printf("Starting UI process for user '%s@%s' for session %d", username, domain, session)
			attr := &os.ProcAttr{
				Sys: &syscall.SysProcAttr{
					Token: syscall.Token(elevatedToken),
				},
				Files: []*os.File{devNull, devNull, devNull},
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

	go checkForUpdates()

	var sessionsPointer *windows.WTS_SESSION_INFO
	var count uint32
	err = windows.WTSEnumerateSessions(0, 0, 1, &sessionsPointer, &count)
	if err != nil {
		serviceError = ErrorEnumerateSessions
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
				go startProcess(session.SessionID)
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
							go startProcess(sessionNotification.SessionID)
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
	if uninstall {
		err = UninstallManager()
		if err != nil {
			log.Printf("Unable to uninstaller manager when quitting: %v", err)
		}
	}
	return
}
