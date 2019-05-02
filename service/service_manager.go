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
	"runtime/debug"
	"sync"
	"syscall"
	"unicode/utf16"
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

//sys wtsQueryUserToken(session uint32, token *windows.Token) (err error) = wtsapi32.WTSQueryUserToken
//sys wtsEnumerateSessions(handle windows.Handle, reserved uint32, version uint32, sessions **wtsSessionInfo, count *uint32) (err error) = wtsapi32.WTSEnumerateSessionsW
//sys wtsFreeMemory(ptr uintptr) = wtsapi32.WTSFreeMemory

const (
	SE_KERNEL_OBJECT               = 6
	DACL_SECURITY_INFORMATION      = 4
	ATTRIBUTE_SECURITY_INFORMATION = 16
)

//sys getSecurityInfo(handle windows.Handle, objectType uint32, si uint32, sidOwner *windows.SID, sidGroup *windows.SID, dacl *uintptr, sacl *uintptr, securityDescriptor *uintptr) (err error) [failretval!=0] = advapi32.GetSecurityInfo
//sys getSecurityDescriptorLength(securityDescriptor uintptr) (len uint32) = advapi32.GetSecurityDescriptorLength

//sys createEnvironmentBlock(block *uintptr, token windows.Token, inheritExisting bool) (err error) = userenv.CreateEnvironmentBlock
//sys destroyEnvironmentBlock(block uintptr) (err error) = userenv.DestroyEnvironmentBlock

func userEnviron(token windows.Token) (env []string, err error) {
	var block uintptr
	err = createEnvironmentBlock(&block, token, false)
	if err != nil {
		return
	}
	offset := uintptr(0)
	for {
		entry := (*[(1 << 30) - 1]uint16)(unsafe.Pointer(block + offset))[:]
		for i, v := range entry {
			if v == 0 {
				entry = entry[:i]
				break
			}
		}
		if len(entry) == 0 {
			break
		}
		env = append(env, string(utf16.Decode(entry)))
		offset += 2 * (uintptr(len(entry)) + 1)
	}
	destroyEnvironmentBlock(block)
	return
}

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

	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		serviceError = ErrorFindAdministratorsSID
		return
	}

	currentProcess, err := windows.GetCurrentProcess()
	if err != nil {
		panic(err)
	}
	var securityAttributes syscall.SecurityAttributes
	err = getSecurityInfo(currentProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nil, nil, nil, nil, &securityAttributes.SecurityDescriptor)
	if err != nil {
		serviceError = ErrorCreateSecurityDescriptor
		return
	}
	defer windows.LocalFree(windows.Handle(securityAttributes.SecurityDescriptor))
	securityAttributes.Length = getSecurityDescriptorLength(securityAttributes.SecurityDescriptor)
	if securityAttributes.Length == 0 {
		serviceError = ErrorCreateSecurityDescriptor
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
	stoppingManager := false

	startProcess = func(session uint32) {
		for {
			if stoppingManager {
				return
			}
			var userToken windows.Token
			err := wtsQueryUserToken(session, &userToken)
			if err != nil {
				return
			}

			//TODO: SECURITY CRITICIAL!
			//TODO: Isn't it better to use an impersonation token and userToken.IsMember instead?
			gs, err := userToken.GetTokenGroups()
			if err != nil {
				log.Printf("Unable to lookup user groups from token: %v", err)
				return
			}
			p := unsafe.Pointer(&gs.Groups[0])
			groups := (*[(1 << 28) - 1]windows.SIDAndAttributes)(p)[:gs.GroupCount]
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

			ourReader, theirReader, theirReaderStr, ourWriter, theirWriter, theirWriterStr, err := inheritableSocketpairEmulation()
			if err != nil {
				log.Printf("Unable to create two inheritable pipes: %v", err)
				return
			}
			ourEvents, theirEvents, theirEventStr, err := inheritableEvents()
			err = IPCServerListen(ourReader, ourWriter, ourEvents)
			if err != nil {
				log.Printf("Unable to listen on IPC pipes: %v", err)
				return
			}
			theirLogMapping, err := ringlogger.Global.ExportInheritableMappingHandleStr()
			if err != nil {
				log.Printf("Unable to export inheritable mapping handle for logging: %v", err)
				return
			}

			env, err := userEnviron(userToken)
			if err != nil {
				log.Printf("Unable to determine user environment: %v", err)
				return
			}

			log.Printf("Starting UI process for user: '%s@%s'", username, domain)
			attr := &os.ProcAttr{
				Sys: &syscall.SysProcAttr{
					Token:             syscall.Token(userToken),
					ProcessAttributes: &securityAttributes,
					ThreadAttributes:  &securityAttributes,
				},
				Files: []*os.File{devNull, devNull, devNull},
				Env:   env,
			}
			proc, err := os.StartProcess(path, []string{path, "/ui", theirReaderStr, theirWriterStr, theirEventStr, theirLogMapping}, attr)
			theirReader.Close()
			theirWriter.Close()
			theirEvents.Close()
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
