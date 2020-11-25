/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

var encryptedFileSd unsafe.Pointer

func randomFileName() string {
	var randBytes [32]byte
	_, err := rand.Read(randBytes[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(randBytes[:]) + ".tmp"
}

func writeEncryptedFile(destination string, overwrite bool, contents []byte) error {
	var err error
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{}))}
	sa.SecurityDescriptor = (*windows.SECURITY_DESCRIPTOR)(atomic.LoadPointer(&encryptedFileSd))
	if sa.SecurityDescriptor == nil {
		sa.SecurityDescriptor, err = windows.SecurityDescriptorFromString("O:SYG:SYD:PAI(A;;FA;;;SY)(A;;SD;;;BA)")
		if err != nil {
			return err
		}
		atomic.StorePointer(&encryptedFileSd, unsafe.Pointer(sa.SecurityDescriptor))
	}
	destination16, err := windows.UTF16FromString(destination)
	if err != nil {
		return err
	}
	tmpDestination := randomFileName()
	tmpDestination16, err := windows.UTF16PtrFromString(tmpDestination)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(tmpDestination16, windows.GENERIC_WRITE|windows.DELETE, 0, sa, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	deleteIt := func() {
		yes := byte(1)
		windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &yes, 1)
	}
	n, err := windows.Write(handle, contents)
	if err != nil {
		deleteIt()
		return err
	}
	if n != len(contents) {
		deleteIt()
		return windows.ERROR_IO_INCOMPLETE
	}
	fileRenameInfo := &struct {
		replaceIfExists byte
		rootDirectory   windows.Handle
		fileNameLength  uint32
		fileName        [windows.MAX_PATH]uint16
	}{replaceIfExists: func() byte {
		if overwrite {
			return 1
		} else {
			return 0
		}
	}(), fileNameLength: uint32(len(destination16) - 1)}
	if len(destination16) > len(fileRenameInfo.fileName) {
		deleteIt()
		return windows.ERROR_BUFFER_OVERFLOW
	}
	copy(fileRenameInfo.fileName[:], destination16[:])
	err = windows.SetFileInformationByHandle(handle, windows.FileRenameInfo, (*byte)(unsafe.Pointer(fileRenameInfo)), uint32(unsafe.Sizeof(*fileRenameInfo)))
	if err != nil {
		deleteIt()
		return err
	}
	return nil
}
