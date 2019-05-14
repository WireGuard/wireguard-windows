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
	} else {
		return fmt.Errorf("Firewall error at %s:%d: %v", file, line, err)
	}
}

func getCurrentProcessSecurityDescriptor() (*wtFwpByteBlob, error) {
	procHandle, err := windows.GetCurrentProcess()
	if err != nil {
		panic(err)
	}
	blob := &wtFwpByteBlob{}
	err = getSecurityInfo(procHandle, cSE_KERNEL_OBJECT, cDACL_SECURITY_INFORMATION, nil, nil, nil, nil, (*uintptr)(unsafe.Pointer(&blob.data)))
	if err != nil {
		return nil, wrapErr(err)
	}
	blob.size = getSecurityDescriptorLength(uintptr(unsafe.Pointer(blob.data)))
	return blob, nil
}

func getCurrentProcessAppId() (*wtFwpByteBlob, error) {
	currentFile, err := os.Executable()
	if err != nil {
		return nil, wrapErr(err)
	}

	curFilePtr, err := windows.UTF16PtrFromString(currentFile)
	if err != nil {
		return nil, wrapErr(err)
	}

	var appId *wtFwpByteBlob
	err = fwpmGetAppIdFromFileName0(curFilePtr, unsafe.Pointer(&appId))
	if err != nil {
		return nil, wrapErr(err)
	}
	return appId, nil
}
