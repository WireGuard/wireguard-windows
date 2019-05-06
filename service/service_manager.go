/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"unsafe"
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
	securityAttributes, err := getCurrentSecurityAttributes()
	if err != nil {
		serviceError = ErrorCreateSecurityDescriptor
		return
	}
	defer windows.LocalFree(windows.Handle(securityAttributes.SecurityDescriptor))

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
	procsLock := sync.Mutex{}
	var startProcess func(session uint32)
	stoppingManager := false

	startProcess = func(session uint32) {
		defer runtime.UnlockOSThread()

		var userToken windows.Token
		err := wtsQueryUserToken(session, &userToken)
		if err != nil {
			return
		}
		defer userToken.Close()
		if !tokenIsMemberOfBuiltInAdministrator(userToken) {
			return
		}
		user, err := userToken.GetTokenUser()
		if err != nil {
			log.Printf("Unable to lookup user from token: %v", err)
			return
		}
		username, domain, accType, err := user.User.Sid.LookupAccount("")
		if err != nil {
			log.Printf("Unable to lookup username from sid: %v", err)
			return
		}
		if accType != windows.SidTypeUser {
			return
		}
		env, err := userEnviron(userToken)
		if err != nil {
			log.Printf("Unable to determine user environment: %v", err)
			return
		}
		userTokenInfo := &UserTokenInfo{}
		userTokenInfo.elevatedToken, err = getElevatedToken(userToken)
		if err != nil {
			log.Printf("Unable to elevate token: %v", err)
		}
		if userTokenInfo.elevatedToken != userToken {
			defer userTokenInfo.elevatedToken.Close()
		}
		userTokenInfo.elevatedEnvironment, err = userEnviron(userTokenInfo.elevatedToken)
		if err != nil {
			log.Printf("Unable to determine elevated environment: %v", err)
			return
		}
		for {
			if stoppingManager {
				return
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
			err = IPCServerListen(ourReader, ourWriter, ourEvents, userTokenInfo)
			if err != nil {
				log.Printf("Unable to listen on IPC pipes: %v", err)
				return
			}
			theirLogMapping, err := ringlogger.Global.ExportInheritableMappingHandleStr()
			if err != nil {
				log.Printf("Unable to export inheritable mapping handle for logging: %v", err)
				return
			}

			log.Printf("Starting UI process for user: '%s@%s'", username, domain)
			attr := &os.ProcAttr{
				Sys: &syscall.SysProcAttr{
					Token: syscall.Token(userToken),

					/* TODO: XXX: BUG: HACK: DO NOT SHIP WITH THIS COMMENT:
					 *  These next two lines are commented out, because:
					 *    - We're uncertain of their correctness, especially with regards to integrity level.
					 *    - The permissions are too tight and they interfere with some UI things like notification
					 *      balloon icons.
					 *  These will be reenabled once we've figured out the right way to do it, and this
					 *  program should not ship until we've done so.

					ProcessAttributes: &securityAttributes,
					ThreadAttributes:  &securityAttributes,
					*/
				},
				Files: []*os.File{devNull, devNull, devNull},
				Env:   env,
			}
			proc, err := os.StartProcess(path, []string{path, "/ui", theirReaderStr, theirWriterStr, theirEventStr, theirLogMapping}, attr)
			theirReader.Close()
			theirWriter.Close()
			theirEvents.Close()
			runtime.UnlockOSThread()
			if err != nil {
				log.Printf("Unable to start manager UI process: %v", err)
				return
			}

			procsLock.Lock()
			procs[session] = proc
			procsLock.Unlock()
			proc.Wait()
			procsLock.Lock()
			delete(procs, session)
			procsLock.Unlock()
			ourReader.Close()
			ourWriter.Close()
			ourEvents.Close()
		}
	}

	go checkForUpdates()

	var sessionsPointer *wtsSessionInfo
	var count uint32
	err = wtsEnumerateSessions(0, 0, 1, &sessionsPointer, &count)
	if err != nil {
		serviceError = ErrorEnumerateSessions
		return
	}
	sessions := *(*[]wtsSessionInfo)(unsafe.Pointer(&struct {
		addr *wtsSessionInfo
		len  int
		cap  int
	}{sessionsPointer, int(count), int(count)}))
	for _, session := range sessions {
		if session.state == wtsActive {
			go startProcess(session.sessionID)
		}
	}
	wtsFreeMemory(uintptr(unsafe.Pointer(sessionsPointer)))

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
				if c.EventType != wtsSessionLogon && c.EventType != wtsSessionLogoff {
					continue
				}
				sessionNotification := (*wtsSessionNotification)(unsafe.Pointer(c.EventData))
				if uintptr(sessionNotification.size) != unsafe.Sizeof(*sessionNotification) {
					log.Printf("Unexpected size of WTSSESSION_NOTIFICATION: %d", sessionNotification.size)
					continue
				}
				if c.EventType == wtsSessionLogoff {
					procsLock.Lock()
					if proc, ok := procs[sessionNotification.sessionID]; ok {
						proc.Kill()
					}
					procsLock.Unlock()
				} else if c.EventType == wtsSessionLogon {
					procsLock.Lock()
					if _, ok := procs[sessionNotification.sessionID]; !ok {
						go startProcess(sessionNotification.sessionID)
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
