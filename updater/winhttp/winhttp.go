/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package winhttp

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Session struct {
	handle _HINTERNET
}

type Connection struct {
	handle  _HINTERNET
	session *Session
	https   bool
}

type Response struct {
	handle     _HINTERNET
	connection *Connection
}

func convertError(err *error) {
	if *err == nil {
		return
	}
	var errno windows.Errno
	if errors.As(*err, &errno) {
		if errno > _WINHTTP_ERROR_BASE && errno <= _WINHTTP_ERROR_LAST {
			*err = Error(errno)
		}
	}
}

func isWin7() bool {
	maj, min, _ := windows.RtlGetNtVersionNumbers()
	return maj < 6 || (maj == 6 && min <= 1)
}

func isWin8DotZeroOrBelow() bool {
	maj, min, _ := windows.RtlGetNtVersionNumbers()
	return maj < 6 || (maj == 6 && min <= 2)
}

func NewSession(userAgent string) (session *Session, err error) {
	session = new(Session)
	defer convertError(&err)
	defer func() {
		if err != nil {
			session.Close()
			session = nil
		}
	}()
	userAgent16, err := windows.UTF16PtrFromString(userAgent)
	if err != nil {
		return
	}
	var proxyFlag uint32 = _WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
	if isWin7() {
		proxyFlag = _WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
	}
	session.handle, err = winHttpOpen(userAgent16, proxyFlag, nil, nil, 0)
	if err != nil {
		return
	}
	var enableHttp2 uint32 = _WINHTTP_PROTOCOL_FLAG_HTTP2
	_ = winHttpSetOption(session.handle, _WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, unsafe.Pointer(&enableHttp2), uint32(unsafe.Sizeof(enableHttp2))) // Don't check return value, in case of old Windows

	if isWin8DotZeroOrBelow() {
		var enableTLS12 uint32 = _WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
		err = winHttpSetOption(session.handle, _WINHTTP_OPTION_SECURE_PROTOCOLS, unsafe.Pointer(&enableTLS12), uint32(unsafe.Sizeof(enableTLS12)))
		if err != nil {
			return
		}
	}

	runtime.SetFinalizer(session, func(session *Session) {
		session.Close()
	})
	return
}

func (session *Session) Close() (err error) {
	defer convertError(&err)
	handle := (_HINTERNET)(atomic.SwapUintptr((*uintptr)(&session.handle), 0))
	if handle == 0 {
		return
	}
	return winHttpCloseHandle(handle)
}

func (session *Session) Connect(server string, port uint16, https bool) (connection *Connection, err error) {
	connection = &Connection{session: session}
	defer convertError(&err)
	defer func() {
		if err != nil {
			connection.Close()
			connection = nil
		}
	}()
	server16, err := windows.UTF16PtrFromString(server)
	if err != nil {
		return
	}
	connection.handle, err = winHttpConnect(session.handle, server16, port, 0)
	if err != nil {
		return
	}
	connection.https = https

	runtime.SetFinalizer(connection, func(connection *Connection) {
		connection.Close()
	})
	return
}

func (connection *Connection) Close() (err error) {
	defer convertError(&err)
	handle := (_HINTERNET)(atomic.SwapUintptr((*uintptr)(&connection.handle), 0))
	if handle == 0 {
		return
	}
	return winHttpCloseHandle(handle)
}

func (connection *Connection) Get(path string, refresh bool) (response *Response, err error) {
	response = &Response{connection: connection}
	defer convertError(&err)
	defer func() {
		if err != nil {
			response.Close()
			response = nil
		}
	}()
	var flags uint32
	if refresh {
		flags |= _WINHTTP_FLAG_REFRESH
	}
	if connection.https {
		flags |= _WINHTTP_FLAG_SECURE
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	get16, err := windows.UTF16PtrFromString("GET")
	if err != nil {
		return
	}
	response.handle, err = winHttpOpenRequest(connection.handle, get16, path16, nil, nil, nil, flags)
	if err != nil {
		return
	}
	err = winHttpSendRequest(response.handle, nil, 0, nil, 0, 0, 0)
	if err != nil {
		return
	}
	err = winHttpReceiveResponse(response.handle, 0)
	if err != nil {
		return
	}

	runtime.SetFinalizer(response, func(response *Response) {
		response.Close()
	})
	return
}

func (response *Response) Length() (length uint64, err error) {
	defer convertError(&err)
	numBuf := make([]uint16, 22)
	numLen := uint32(len(numBuf) * 2)
	err = winHttpQueryHeaders(response.handle, _WINHTTP_QUERY_CONTENT_LENGTH, nil, unsafe.Pointer(&numBuf[0]), &numLen, nil)
	if err != nil {
		return
	}
	length, err = strconv.ParseUint(windows.UTF16ToString(numBuf[:numLen]), 10, 64)
	if err != nil {
		return
	}
	return
}

func (response *Response) Read(p []byte) (n int, err error) {
	defer convertError(&err)
	if len(p) == 0 {
		return 0, nil
	}
	var bytesRead uint32
	err = winHttpReadData(response.handle, &p[0], uint32(len(p)), &bytesRead)
	if err != nil {
		return 0, nil
	}
	if bytesRead == 0 || int(bytesRead) < 0 {
		return 0, io.EOF
	}
	return int(bytesRead), nil
}

func (response *Response) Close() (err error) {
	defer convertError(&err)
	handle := (_HINTERNET)(atomic.SwapUintptr((*uintptr)(&response.handle), 0))
	if handle == 0 {
		return
	}
	return winHttpCloseHandle(handle)
}

func (error Error) Error() string {
	var message [2048]uint16
	n, err := windows.FormatMessage(windows.FORMAT_MESSAGE_FROM_HMODULE|windows.FORMAT_MESSAGE_IGNORE_INSERTS|windows.FORMAT_MESSAGE_MAX_WIDTH_MASK,
		modwinhttp.Handle(), uint32(error), 0, message[:], nil)
	if err != nil {
		return fmt.Sprintf("WinHTTP error #%d", error)
	}
	return strings.TrimSpace(windows.UTF16ToString(message[:n]))
}
