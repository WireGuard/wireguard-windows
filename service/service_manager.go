/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.zx2c4.com/wireguard/windows/conf"
	"log"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

const (
	wtsSessionLogon  uint32 = 5
	wtsSessionLogoff uint32 = 6
)

type wtsState int

const (
	wtsActive wtsState = iota
	wtsConnected
	wtsConnectQuery
	wtsShadow
	wtsDisconnected
	wtsIdle
	wtsListen
	wtsReset
	wtsDown
	wtsInit
)

type wtsSessionNotification struct {
	size      uint32
	sessionID uint32
}

type wtsSessionInfo struct {
	sessionID         uint32
	windowStationName *uint16
	state             wtsState
}

type wellKnownSidType uint32

//sys wtfQueryUserToken(session uint32, token *windows.Token) (err error) = wtsapi32.WTSQueryUserToken
//sys wtsEnumerateSessions(handle windows.Handle, reserved uint32, version uint32, sessions **wtsSessionInfo, count *uint32) (err error) = wtsapi32.WTSEnumerateSessionsW
//sys wtsFreeMemory(ptr uintptr) = wtsapi32.WTSFreeMemory

type managerService struct{}

type elogger struct {
	*eventlog.Log
}

func (elog elogger) Write(p []byte) (n int, err error) {
	msg := string(p)
	n = len(msg)
	err = elog.Warning(1, msg)
	return
}

func (service *managerService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var elog *eventlog.Log
	var err error
	serviceError := ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = determineErrorCode(err, serviceError)
		logErr := combineErrors(err, serviceError)
		if logErr != nil {
			if elog != nil {
				elog.Error(1, logErr.Error())
			} else {
				fmt.Println(logErr.Error())
			}
		}
		changes <- svc.Status{State: svc.StopPending}
	}()

	//TODO: remember to clean this up in the msi uninstaller
	eventlog.InstallAsEventCreate("WireGuard", eventlog.Info|eventlog.Warning|eventlog.Error)
	elog, err = eventlog.Open("WireGuard")
	if err != nil {
		serviceError = ErrorEventlogOpen
		return
	}
	log.SetOutput(elogger{elog})
	defer func() {
		if x := recover(); x != nil {
			elog.Error(1, fmt.Sprintf("%v:\n%s", x, string(debug.Stack())))
			panic(x)
		}
	}()

	path, err := os.Executable()
	if err != nil {
		serviceError = ErrorDetermineExecutablePath
		return
	}

	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		serviceError = ErrorFindAdministratorsSID
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
	procsLock := sync.Mutex{}
	var startProcess func(session uint32)

	startProcess = func(session uint32) {
		for {
			var userToken windows.Token
			err := wtfQueryUserToken(session, &userToken)
			if err != nil {
				return
			}

			//TODO: SECURITY CRITICIAL!
			//TODO: Isn't it better to use an impersonation token and userToken.IsMember instead?
			gs, err := userToken.GetTokenGroups()
			if err != nil {
				elog.Error(1, "Unable to lookup user groups from token: "+err.Error())
				return
			}
			p := unsafe.Pointer(&gs.Groups[0])
			//TODO: x/sys/windows/svc/security.go uses 2 << 20, but shouldn't this be 1 << 20? Send upstream
			groups := (*[1 << 20]windows.SIDAndAttributes)(p)[:gs.GroupCount]
			isAdmin := false
			for _, g := range groups {
				if windows.EqualSid(g.Sid, adminSid) {
					isAdmin = true
					break
				}
			}
			if !isAdmin {
				return
			}

			user, err := userToken.GetTokenUser()
			if err != nil {
				elog.Error(1, "Unable to lookup user from token: "+err.Error())
				return
			}
			username, domain, accType, err := user.User.Sid.LookupAccount("")
			if err != nil {
				elog.Error(1, "Unable to lookup username from sid: "+err.Error())
				return
			}
			if accType != windows.SidTypeUser {
				return
			}

			ourReader, theirReader, theirReaderStr, ourWriter, theirWriter, theirWriterStr, err := inheritableSocketpairEmulation()
			if err != nil {
				elog.Error(1, "Unable to create two inheritable pipes: "+err.Error())
				return
			}
			ourEvents, theirEvents, theirEventStr, err := inheritableEvents()
			err = IPCServerListen(ourReader, ourWriter, ourEvents)
			if err != nil {
				elog.Error(1, "Unable to listen on IPC pipes: "+err.Error())
				return
			}

			elog.Info(1, "Starting UI process for user: "+username+", domain: "+domain)
			attr := &os.ProcAttr{
				Sys: &syscall.SysProcAttr{
					Token: syscall.Token(userToken),
				},
				Files: []*os.File{devNull, devNull, devNull},
			}
			proc, err := os.StartProcess(path, []string{path, "/ui", theirReaderStr, theirWriterStr, theirEventStr}, attr)
			theirReader.Close()
			theirWriter.Close()
			theirEvents.Close()
			if err != nil {
				elog.Error(1, "Unable to start manager UI process: "+err.Error())
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
					elog.Error(1, "Unexpected size of WTSSESSION_NOTIFICATION: "+strconv.Itoa(int(sessionNotification.size)))
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
				elog.Info(1, fmt.Sprintf("Unexpected service control request #%d\n", c))
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	procsLock.Lock()
	for _, proc := range procs {
		proc.Kill()
	}
	procsLock.Unlock()
	if uninstall {
		err = UninstallManager()
		if err != nil {
			elog.Error(1, "Unable to uninstaller manager when quitting: "+err.Error())
		}
	}
	return
}
