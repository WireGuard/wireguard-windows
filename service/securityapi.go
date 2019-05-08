/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
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

//sys wtsQueryUserToken(session uint32, token *windows.Token) (err error) = wtsapi32.WTSQueryUserToken
//sys wtsEnumerateSessions(handle windows.Handle, reserved uint32, version uint32, sessions **wtsSessionInfo, count *uint32) (err error) = wtsapi32.WTSEnumerateSessionsW
//sys wtsFreeMemory(ptr uintptr) = wtsapi32.WTSFreeMemory

const (
	SE_KERNEL_OBJECT = 6

	SE_GROUP_LOGON_ID          = 0xC0000000
	SE_GROUP_ENABLED           = 0x00000004
	SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010

	ACL_REVISION = 2

	PROCESS_TERMINATE                 = 0x0001
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_SET_SESSIONID             = 0x0004
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	OWNER_SECURITY_INFORMATION            = 0x00000001
	GROUP_SECURITY_INFORMATION            = 0x00000002
	DACL_SECURITY_INFORMATION             = 0x00000004
	SACL_SECURITY_INFORMATION             = 0x00000008
	LABEL_SECURITY_INFORMATION            = 0x00000010
	ATTRIBUTE_SECURITY_INFORMATION        = 0x00000020
	SCOPE_SECURITY_INFORMATION            = 0x00000040
	BACKUP_SECURITY_INFORMATION           = 0x00010000
	PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
	PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
	UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
	UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000

	AclRevisionInformation = 1
	AclSizeInformation     = 2
)

type ACL_SIZE_INFORMATION struct {
	aceCount      uint32
	aclBytesInUse uint32
	aclBytesFree  uint32
}
type ACE_HEADER struct {
	aceType  byte
	aceFlags byte
	aceSize  uint16
}

//sys getSecurityInfo(handle windows.Handle, objectType uint32, si uint32, owner *uintptr, group *uintptr, dacl *uintptr, sacl *uintptr, securityDescriptor *uintptr) (err error) [failretval!=0] = advapi32.GetSecurityInfo
//sys addAccessAllowedAce(acl *byte, aceRevision uint32, accessmask uint32, sid *windows.SID) (err error) = advapi32.AddAccessAllowedAce
//sys setSecurityDescriptorDacl(securityDescriptor *byte, daclPresent bool, dacl *byte, defaulted bool) (err error) = advapi32.SetSecurityDescriptorDacl
//sys setSecurityDescriptorSacl(securityDescriptor *byte, saclPresent bool, sacl *byte, defaulted bool) (err error) = advapi32.SetSecurityDescriptorSacl
//sys getAclInformation(acl *byte, info *ACL_SIZE_INFORMATION, len uint32, infoclass uint32) (err error) = advapi32.GetAclInformation
//sys getAce(acl *byte, index uint32, ace **ACE_HEADER) (err error) = advapi32.GetAce
//sys addAce(acl *byte, revision uint32, index uint32, ace *ACE_HEADER, lenAce uint32) (err error) = advapi32.AddAce
//sys initializeAcl(acl *byte, len uint32, revision uint32) (err error) = advapi32.InitializeAcl
//sys makeAbsoluteSd(selfRelativeSecurityDescriptor uintptr, absoluteSecurityDescriptor *byte, absoluteSecurityDescriptorSize *uint32, dacl *byte, daclSize *uint32, sacl *byte, saclSize *uint32, owner *byte, ownerSize *uint32, primaryGroup *byte, primaryGroupSize *uint32) (err error) = advapi32.MakeAbsoluteSD
//sys makeSelfRelativeSd(absoluteSecurityDescriptor *byte, relativeSecurityDescriptor *byte, relativeSecurityDescriptorSize *uint32) (err error) = advapi32.MakeSelfRelativeSD

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

func sliceToSecurityAttributes(sa []byte) *syscall.SecurityAttributes {
	return &syscall.SecurityAttributes{
		Length:             uint32(len(sa)),
		SecurityDescriptor: uintptr(unsafe.Pointer(&sa[0])),
	}
}

func getSecurityAttributes(mainToken windows.Token, tokenThatHasLogonSession windows.Token) ([]byte, error) {
	gs, err := tokenThatHasLogonSession.GetTokenGroups()
	if err != nil {
		return nil, err
	}
	var logonSid *windows.SID
	groups := (*[(1 << 28) - 1]windows.SIDAndAttributes)(unsafe.Pointer(&gs.Groups[0]))[:gs.GroupCount]
	for _, g := range groups {
		if g.Attributes&SE_GROUP_LOGON_ID != 0 && g.Attributes&SE_GROUP_ENABLED != 0 {
			logonSid = g.Sid
			break
		}
	}
	if logonSid == nil {
		return nil, errors.New("Unable to find logon SID")
	}

	var originalSecurityDescriptor uintptr
	err = getSecurityInfo(windows.Handle(mainToken), SE_KERNEL_OBJECT, ATTRIBUTE_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION|SCOPE_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION, nil, nil, nil, nil, &originalSecurityDescriptor)
	if err != nil {
		return nil, err
	}
	var (
		absoluteSecurityDescriptorSize uint32
		daclSize                       uint32
		saclSize                       uint32
		ownerSize                      uint32
		primaryGroupSize               uint32
	)
	err = makeAbsoluteSd(originalSecurityDescriptor, nil, &absoluteSecurityDescriptorSize, nil, &daclSize, nil, &saclSize, nil, &ownerSize, nil, &primaryGroupSize)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		windows.LocalFree(windows.Handle(originalSecurityDescriptor))
		return nil, fmt.Errorf("Expected insufficient buffer from MakeAbsoluteSd, but got: %v", err)
	}
	absoluteSecurityDescriptor := make([]byte, absoluteSecurityDescriptorSize)
	dacl := make([]byte, daclSize)
	sacl := make([]byte, saclSize)
	owner := make([]byte, ownerSize)
	primaryGroup := make([]byte, primaryGroupSize)
	err = makeAbsoluteSd(originalSecurityDescriptor, &absoluteSecurityDescriptor[0], &absoluteSecurityDescriptorSize, &dacl[0], &daclSize, &sacl[0], &saclSize, &owner[0], &ownerSize, &primaryGroup[0], &primaryGroupSize)
	if err != nil {
		windows.LocalFree(windows.Handle(originalSecurityDescriptor))
		return nil, err
	}
	windows.LocalFree(windows.Handle(originalSecurityDescriptor))

	var daclInfo ACL_SIZE_INFORMATION
	err = getAclInformation(&dacl[0], &daclInfo, uint32(unsafe.Sizeof(daclInfo)), AclSizeInformation)
	if err != nil {
		return nil, err
	}
	newDacl := make([]byte, daclInfo.aclBytesInUse*2)
	err = initializeAcl(&newDacl[0], uint32(len(newDacl)), ACL_REVISION)
	if err != nil {
		return nil, err
	}
	var ace *ACE_HEADER
	for i := uint32(0); i < daclInfo.aceCount; i++ {
		err = getAce(&dacl[0], i, &ace)
		if err != nil {
			return nil, err
		}
		err = addAce(&newDacl[0], ACL_REVISION, ^uint32(0), ace, uint32(ace.aceSize))
		if err != nil {
			return nil, err
		}
	}
	runtime.KeepAlive(dacl)
	err = addAccessAllowedAce(&newDacl[0], ACL_REVISION, PROCESS_QUERY_LIMITED_INFORMATION, logonSid)
	if err != nil {
		return nil, err
	}
	runtime.KeepAlive(gs)
	err = setSecurityDescriptorDacl(&absoluteSecurityDescriptor[0], true, &newDacl[0], false)
	if err != nil {
		return nil, err
	}
	//TODO: This should not be required!! But right now we can't give the process the high integrity SACL, which is unfortunate. So we unset it.
	err = setSecurityDescriptorSacl(&absoluteSecurityDescriptor[0], false, nil, true)
	if err != nil {
		return nil, err
	}
	var selfRelativeSecurityDescriptorSize uint32
	err = makeSelfRelativeSd(&absoluteSecurityDescriptor[0], nil, &selfRelativeSecurityDescriptorSize)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("Expected insufficient buffer from MakeSelfRelativeSd, but got: %v", err)
	}
	relativeSecurityDescriptor := make([]byte, selfRelativeSecurityDescriptorSize)
	err = makeSelfRelativeSd(&absoluteSecurityDescriptor[0], &relativeSecurityDescriptor[0], &selfRelativeSecurityDescriptorSize)
	if err != nil {
		return nil, err
	}
	runtime.KeepAlive(absoluteSecurityDescriptor)
	runtime.KeepAlive(newDacl)
	runtime.KeepAlive(sacl)
	runtime.KeepAlive(owner)
	runtime.KeepAlive(primaryGroup)

	return relativeSecurityDescriptor, nil
}
