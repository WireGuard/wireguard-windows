/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package dpapi

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dpCRYPTPROTECT_UI_FORBIDDEN      uint32 = 0x1
	dpCRYPTPROTECT_LOCAL_MACHINE     uint32 = 0x4
	dpCRYPTPROTECT_CRED_SYNC         uint32 = 0x8
	dpCRYPTPROTECT_AUDIT             uint32 = 0x10
	dpCRYPTPROTECT_NO_RECOVERY       uint32 = 0x20
	dpCRYPTPROTECT_VERIFY_PROTECTION uint32 = 0x40
	dpCRYPTPROTECT_CRED_REGENERATE   uint32 = 0x80
)

type dpBlob struct {
	len  uint32
	data uintptr
}

func bytesToBlob(bytes []byte) *dpBlob {
	blob := &dpBlob{}
	blob.len = uint32(len(bytes))
	if len(bytes) > 0 {
		blob.data = uintptr(unsafe.Pointer(&bytes[0]))
	}
	return blob
}

//sys	cryptProtectData(dataIn *dpBlob, name *uint16, optionalEntropy *dpBlob, reserved uintptr, promptStruct uintptr, flags uint32, dataOut *dpBlob) (err error) = crypt32.CryptProtectData

func Encrypt(data []byte, name string) ([]byte, error) {
	out := dpBlob{}
	err := cryptProtectData(bytesToBlob(data), windows.StringToUTF16Ptr(name), nil, 0, 0, dpCRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, errors.New("Unable to encrypt DPAPI protected data: " + err.Error())
	}

	outSlice := *(*[]byte)(unsafe.Pointer(&(struct {
		addr uintptr
		len  int
		cap  int
	}{out.data, int(out.len), int(out.len)})))
	ret := make([]byte, len(outSlice))
	copy(ret, outSlice)
	windows.LocalFree(windows.Handle(out.data))

	return ret, nil
}

//sys	cryptUnprotectData(dataIn *dpBlob, name **uint16, optionalEntropy *dpBlob, reserved uintptr, promptStruct uintptr, flags uint32, dataOut *dpBlob) (err error) = crypt32.CryptUnprotectData

func Decrypt(data []byte, name string) ([]byte, error) {
	out := dpBlob{}
	var outName *uint16
	utf16Name, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}

	err = cryptUnprotectData(bytesToBlob(data), &outName, nil, 0, 0, dpCRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, errors.New("Unable to decrypt DPAPI protected data: " + err.Error())
	}

	outSlice := *(*[]byte)(unsafe.Pointer(&(struct {
		addr uintptr
		len  int
		cap  int
	}{out.data, int(out.len), int(out.len)})))
	ret := make([]byte, len(outSlice))
	copy(ret, outSlice)
	windows.LocalFree(windows.Handle(out.data))

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
		a = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(a)) + 2))
		b = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(b)) + 2))
	}
	runtime.KeepAlive(utf16Name)
	windows.LocalFree(windows.Handle(unsafe.Pointer(outName)))

	if different {
		return nil, errors.New("The input name does not match the stored name")
	}

	return ret, nil
}
