/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func runTransaction(session uintptr, operation wfpObjectInstaller) error {
	err := fwpmTransactionBegin0(session, 0)
	if err != nil {
		return wrapErr(err)
	}

	err = operation(session)
	if err != nil {
		fwpmTransactionAbort0(session)
		return wrapErr(err)
	}

	err = fwpmTransactionCommit0(session)
	if err != nil {
		fwpmTransactionAbort0(session)
		return wrapErr(err)
	}

	return nil
}

func createWtFwpmDisplayData0(name, description string) (*wtFwpmDisplayData0, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, wrapErr(err)
	}

	descriptionPtr, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, wrapErr(err)
	}

	return &wtFwpmDisplayData0{
		name:        namePtr,
		description: descriptionPtr,
	}, nil
}

func filterWeight(weight uint8) wtFwpValue0 {
	return wtFwpValue0{
		_type: cFWP_UINT8,
		value: uintptr(weight),
	}
}

func wrapErr(err error) error {
	if _, ok := err.(syscall.Errno); !ok {
		return err
	}
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("Firewall error at unknown location: %v", err)
	}
	return fmt.Errorf("Firewall error at %s:%d: %v", file, line, err)
}

func getCurrentProcessSecurityDescriptor() (*wtFwpByteBlob, error) {
	processToken, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, wrapErr(err)
	}
	defer processToken.Close()
	gs, err := processToken.GetTokenGroups()
	if err != nil {
		return nil, wrapErr(err)
	}
	var sid *windows.SID
	groups := (*[(1 << 28) - 1]windows.SIDAndAttributes)(unsafe.Pointer(&gs.Groups[0]))[:gs.GroupCount]
	for _, g := range groups {
		if g.Attributes != windows.SE_GROUP_ENABLED|windows.SE_GROUP_ENABLED_BY_DEFAULT|windows.SE_GROUP_OWNER {
			continue
		}
		// We could be checking != 6, but hopefully Microsoft will update
		// RtlCreateServiceSid to use SHA2, which will then likely bump
		// this up. So instead just roll with a minimum.
		if !g.Sid.IsValid() || g.Sid.IdentifierAuthority() != windows.SECURITY_NT_AUTHORITY || g.Sid.SubAuthorityCount() < 6 || g.Sid.SubAuthority(0) != 80 {
			continue
		}
		sid = g.Sid
		break
	}
	if sid == nil {
		return nil, wrapErr(windows.ERROR_NO_SUCH_GROUP)
	}

	access := &wtExplicitAccess{
		accessPermissions: cFWP_ACTRL_MATCH_FILTER,
		accessMode:        cGRANT_ACCESS,
		trustee: wtTrustee{
			trusteeForm: cTRUSTEE_IS_SID,
			trusteeType: cTRUSTEE_IS_GROUP,
			sid:         sid,
		},
	}
	blob := &wtFwpByteBlob{}
	err = buildSecurityDescriptor(nil, nil, 1, access, 0, nil, nil, &blob.size, &blob.data)
	if err != nil {
		return nil, wrapErr(err)
	}
	return blob, nil
}

func getCurrentProcessAppID() (*wtFwpByteBlob, error) {
	currentFile, err := os.Executable()
	if err != nil {
		return nil, wrapErr(err)
	}

	curFilePtr, err := windows.UTF16PtrFromString(currentFile)
	if err != nil {
		return nil, wrapErr(err)
	}

	var appID *wtFwpByteBlob
	err = fwpmGetAppIdFromFileName0(curFilePtr, unsafe.Pointer(&appID))
	if err != nil {
		return nil, wrapErr(err)
	}
	return appID, nil
}
