// Copyright 2010 The win Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package win

import (
	"syscall"
	"unsafe"
)

const (
	S_OK           = HRESULT(0x00000000)
	S_FALSE        = HRESULT(0x00000001)
	E_UNEXPECTED   = HRESULT(-((0x8000FFFF ^ 0xFFFFFFFF) + 1))
	E_NOTIMPL      = HRESULT(-((0x80004001 ^ 0xFFFFFFFF) + 1))
	E_OUTOFMEMORY  = HRESULT(-((0x8007000E ^ 0xFFFFFFFF) + 1))
	E_INVALIDARG   = HRESULT(-((0x80070057 ^ 0xFFFFFFFF) + 1))
	E_NOINTERFACE  = HRESULT(-((0x80004002 ^ 0xFFFFFFFF) + 1))
	E_POINTER      = HRESULT(-((0x80004003 ^ 0xFFFFFFFF) + 1))
	E_HANDLE       = HRESULT(-((0x80070006 ^ 0xFFFFFFFF) + 1))
	E_ABORT        = HRESULT(-((0x80004004 ^ 0xFFFFFFFF) + 1))
	E_FAIL         = HRESULT(-((0x80004005 ^ 0xFFFFFFFF) + 1))
	E_ACCESSDENIED = HRESULT(-((0x80070005 ^ 0xFFFFFFFF) + 1))
	E_PENDING      = HRESULT(-((0x8000000A ^ 0xFFFFFFFF) + 1))
)

const (
	FALSE = 0
	TRUE  = 1
)

type (
	BOOL    int32
	HRESULT int32
)

func SUCCEEDED(hr HRESULT) bool {
	return hr >= 0
}

func FAILED(hr HRESULT) bool {
	return hr < 0
}

func MAKEWORD(lo, hi byte) uint16 {
	return uint16(uint16(lo) | ((uint16(hi)) << 8))
}

func LOBYTE(w uint16) byte {
	return byte(w)
}

func HIBYTE(w uint16) byte {
	return byte(w >> 8 & 0xff)
}

func MAKELONG(lo, hi uint16) uint32 {
	return uint32(uint32(lo) | ((uint32(hi)) << 16))
}

func LOWORD(dw uint32) uint16 {
	return uint16(dw)
}

func HIWORD(dw uint32) uint16 {
	return uint16(dw >> 16 & 0xffff)
}

func UTF16PtrToString(s *uint16) string {
	if s == nil {
		return ""
	}
	return syscall.UTF16ToString((*[1 << 29]uint16)(unsafe.Pointer(s))[0:])
}

func MAKEINTRESOURCE(id uintptr) *uint16 {
	return (*uint16)(unsafe.Pointer(id))
}

func BoolToBOOL(value bool) BOOL {
	if value {
		return 1
	}

	return 0
}
