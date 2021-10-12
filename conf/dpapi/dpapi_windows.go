/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package dpapi

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func bytesToBlob(bytes []byte) *windows.DataBlob {
	blob := &windows.DataBlob{Size: uint32(len(bytes))}
	if len(bytes) > 0 {
		blob.Data = &bytes[0]
	}
	return blob
}

func Encrypt(data []byte, name string) ([]byte, error) {
	out := windows.DataBlob{}
	err := windows.CryptProtectData(bytesToBlob(data), windows.StringToUTF16Ptr(name), nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt DPAPI protected data: %w", err)
	}
	ret := make([]byte, out.Size)
	copy(ret, unsafe.Slice(out.Data, out.Size))
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return ret, nil
}

func Decrypt(data []byte, name string) ([]byte, error) {
	out := windows.DataBlob{}
	var outName *uint16
	utf16Name, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	err = windows.CryptUnprotectData(bytesToBlob(data), &outName, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt DPAPI protected data: %w", err)
	}
	ret := make([]byte, out.Size)
	copy(ret, unsafe.Slice(out.Data, out.Size))
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))

	// Note: this ridiculous open-coded strcmp is not constant time.
	different := false
	a := outName
	b := utf16Name
	for {
		if *a != *b {
			different = true
			break
		}
		if *a == 0 || *b == 0 {
			break
		}
		a = (*uint16)(unsafe.Add(unsafe.Pointer(a), 2))
		b = (*uint16)(unsafe.Add(unsafe.Pointer(b), 2))
	}
	runtime.KeepAlive(utf16Name)
	windows.LocalFree(windows.Handle(unsafe.Pointer(outName)))

	if different {
		return nil, errors.New("input name does not match the stored name")
	}

	return ret, nil
}
