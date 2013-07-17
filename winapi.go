// Copyright 2010 The go-winapi Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winapi

import (
	"reflect"
	"runtime"
	"strconv"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func init() {
	runtime.LockOSThread()
}

const (
	S_OK           = 0x00000000
	S_FALSE        = 0x00000001
	E_UNEXPECTED   = 0x8000FFFF
	E_NOTIMPL      = 0x80004001
	E_OUTOFMEMORY  = 0x8007000E
	E_INVALIDARG   = 0x80070057
	E_NOINTERFACE  = 0x80004002
	E_POINTER      = 0x80004003
	E_HANDLE       = 0x80070006
	E_ABORT        = 0x80004004
	E_FAIL         = 0x80004005
	E_ACCESSDENIED = 0x80070005
	E_PENDING      = 0x8000000A
)

const (
	FALSE = 0
	TRUE  = 1
)

type (
	BOOL    int32
	HRESULT int32
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func MustLoadLibrary(name string) uintptr {
	lib, err := syscall.LoadLibrary(name)
	if err != nil {
		panic(err)
	}

	return uintptr(lib)
}

func MustGetProcAddress(lib uintptr, name string) uintptr {
	addr, err := syscall.GetProcAddress(syscall.Handle(lib), name)
	if err != nil {
		panic(err)
	}

	return uintptr(addr)
}

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

func GoStringToPtr(v string) uintptr {
	if v == "" {
		return 0
	}

	u := utf16.Encode([]rune(v))
	u = append(u, 0)

	return uintptr(unsafe.Pointer(&u[0]))
}

func PtrToGoString(v uintptr) string {
	if v == 0 {
		return ""
	}

	vp := (*[1 << 29]uint16)(unsafe.Pointer(v))
	size := 0
	for ; vp[size] != 0; size++ {
	}

	return string(utf16.Decode(vp[:size]))
}

func Ptr(i interface{}) (ret uintptr) {
	v := reflect.ValueOf(i)
	switch v.Kind() {
	case reflect.Slice, reflect.Func, reflect.Ptr, reflect.UnsafePointer:
		ret = v.Pointer()
		break

	case reflect.Uintptr, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
		ret = uintptr(v.Uint())
		break

	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int:
		ret = uintptr(v.Int())
		break

	case reflect.String:
		ret = GoStringToPtr(v.String())
		break

	case reflect.Bool:
		if v.Bool() {
			ret = 1
		} else {
			ret = 0
		}
		break
	}

	return
}

func allNumber(s string) bool {
	for _, v := range s {
		if !(v >= '0' && v <= '9') {
			return false
		}
	}

	return true
}

func ResourceNameToUTF16Ptr(name string) (id *uint16) {
	number := allNumber(name)
	if number {
		idNumber, err := strconv.Atoi(name)
		if err != nil {
			id = syscall.StringToUTF16Ptr(name)
		} else {
			id = MAKEINTRESOURCE(uintptr(idNumber))
		}
	} else {
		id = syscall.StringToUTF16Ptr(name)
	}

	return
}
