/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
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

//sys wtsQueryUserToken(session uint32, token *windows.Token) (err error) = wtsapi32.WTSQueryUserToken
//sys wtsEnumerateSessions(handle windows.Handle, reserved uint32, version uint32, sessions **wtsSessionInfo, count *uint32) (err error) = wtsapi32.WTSEnumerateSessionsW
//sys wtsFreeMemory(ptr uintptr) = wtsapi32.WTSFreeMemory

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
