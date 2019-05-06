/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"errors"
	"golang.org/x/sys/windows"
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

//sys wtsQueryUserToken(session uint32, token *windows.Token) (err error) = wtsapi32.WTSQueryUserToken
//sys wtsEnumerateSessions(handle windows.Handle, reserved uint32, version uint32, sessions **wtsSessionInfo, count *uint32) (err error) = wtsapi32.WTSEnumerateSessionsW
//sys wtsFreeMemory(ptr uintptr) = wtsapi32.WTSFreeMemory

const (
	SE_KERNEL_OBJECT = 6

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
	//TODO: SECURITY CRITICIAL!
	//TODO: Isn't it better to use an impersonation token or userToken.IsMember instead?
	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	gs, err := token.GetTokenGroups()
	if err != nil {
		return false
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
	return isAdmin
}
