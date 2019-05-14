/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	WTS_CONSOLE_CONNECT        = 0x1
	WTS_CONSOLE_DISCONNECT     = 0x2
	WTS_REMOTE_CONNECT         = 0x3
	WTS_REMOTE_DISCONNECT      = 0x4
	WTS_SESSION_LOGON          = 0x5
	WTS_SESSION_LOGOFF         = 0x6
	WTS_SESSION_LOCK           = 0x7
	WTS_SESSION_UNLOCK         = 0x8
	WTS_SESSION_REMOTE_CONTROL = 0x9
	WTS_SESSION_CREATE         = 0xa
	WTS_SESSION_TERMINATE      = 0xb
)

const (
	WTSActive       = 0
	WTSConnected    = 1
	WTSConnectQuery = 2
	WTSShadow       = 3
	WTSDisconnected = 4
	WTSIdle         = 5
	WTSListen       = 6
	WTSReset        = 7
	WTSDown         = 8
	WTSInit         = 9
)

type WTS_SESSION_NOTIFICATION struct {
	Size      uint32
	SessionID uint32
}

type WTS_SESSION_INFO struct {
	SessionID         uint32
	WindowStationName *uint16
	State             uint32
}

//sys	wtsQueryUserToken(session uint32, token *windows.Token) (err error) = wtsapi32.WTSQueryUserToken
//sys	wtsEnumerateSessions(handle windows.Handle, reserved uint32, version uint32, sessions **WTS_SESSION_INFO, count *uint32) (err error) = wtsapi32.WTSEnumerateSessionsW
//sys	wtsFreeMemory(ptr uintptr) = wtsapi32.WTSFreeMemory

// TEMP //

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

const (
	SE_PRIVILEGE_REMOVED uint32 = 0X00000004
	TOKEN_READ uint32 = 0x00020008
	TOKEN_WRITE uint32 = 0x000200e0
	TokenPrivileges uint32 = 3
)

//sys adjustTokenPrivileges(token windows.Token, disableAllPrivileges bool, newstate *TOKEN_PRIVILEGES, buflen uint32, prevstate *TOKEN_PRIVILEGES, returnlen *uint32) (err error) = advapi32.AdjustTokenPrivileges
//sys openProcessToken(processHandle windows.Handle, accessFlags uint32, token *windows.Token) (err error) = advapi32.OpenProcessToken

// END TEMP //

const (
	SE_GROUP_ENABLED           = 0x00000004
	SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010
)

func tokenIsElevated(token windows.Token) bool {
	var isElevated uint32
	var outLen uint32
	err := windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&isElevated)), uint32(unsafe.Sizeof(isElevated)), &outLen)
	if err != nil {
		return false
	}
	return outLen == uint32(unsafe.Sizeof(isElevated)) && isElevated != 0
}

func getElevatedToken(token windows.Token) (windows.Token, error) {
	if tokenIsElevated(token) {
		return token, nil
	}
	var linkedToken windows.Token
	var outLen uint32
	err := windows.GetTokenInformation(token, windows.TokenLinkedToken, (*byte)(unsafe.Pointer(&linkedToken)), uint32(unsafe.Sizeof(linkedToken)), &outLen)
	if err != nil {
		return windows.Token(0), err
	}
	if tokenIsElevated(linkedToken) {
		return linkedToken, nil
	}
	linkedToken.Close()
	return windows.Token(0), errors.New("the linked token is not elevated")
}

func tokenIsMemberOfBuiltInAdministrator(token windows.Token) bool {
	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	gs, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	groups := (*[(1 << 28) - 1]windows.SIDAndAttributes)(unsafe.Pointer(&gs.Groups[0]))[:gs.GroupCount]
	isAdmin := false
	for _, g := range groups {
		if (g.Attributes&SE_GROUP_USE_FOR_DENY_ONLY != 0 || g.Attributes&SE_GROUP_ENABLED != 0) && windows.EqualSid(g.Sid, adminSid) {
			isAdmin = true
			break
		}
	}
	runtime.KeepAlive(gs)
	return isAdmin
}

func dropAllPrivileges() error {
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	var processToken windows.Token
	err = openProcessToken(processHandle, TOKEN_READ | TOKEN_WRITE, (*windows.Token)(unsafe.Pointer(&processToken)))
	if err != nil {
		return err
	}
	defer processToken.Close()
	var bufferSizeRequired uint32
	_ = windows.GetTokenInformation(processToken, TokenPrivileges, nil, 0, (*uint32)(unsafe.Pointer(&bufferSizeRequired)))
	if bufferSizeRequired == 0  {
		return errors.New("GetTokenInformation failed to provide a buffer size")
	}
	buffer := make([]uint8, bufferSizeRequired)
	var bytesWritten uint32
	err = windows.GetTokenInformation(processToken, TokenPrivileges, (*uint8)(unsafe.Pointer(&buffer[0])), (uint32)(len(buffer)), (*uint32)(unsafe.Pointer(&bytesWritten)))
	if err != nil {
		return err
	}
	if bytesWritten != bufferSizeRequired {
		return errors.New("GetTokenInformation returned incomplete data")
	}
	tokenPrivileges := (*TOKEN_PRIVILEGES)(unsafe.Pointer(&buffer[0]))
	privs := (*[1024]LUID_AND_ATTRIBUTES)(unsafe.Pointer(&buffer[unsafe.Sizeof(tokenPrivileges.PrivilegeCount)]))
	for i := uint32(0); i < tokenPrivileges.PrivilegeCount; i++ {
		privs[i].Attributes = SE_PRIVILEGE_REMOVED
	}
	err = adjustTokenPrivileges(processToken, false, tokenPrivileges, 0, nil, nil)
	if err != nil {
		return err
	}
	return nil
}
