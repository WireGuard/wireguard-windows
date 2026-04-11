/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
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
	session.handle, err = winHttpOpen(userAgent16, _WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, nil, nil, 0)
	if err != nil {
		return
	}
	var enableHttp uint32 = _WINHTTP_PROTOCOL_FLAG_HTTP2 | _WINHTTP_PROTOCOL_FLAG_HTTP3
	if winHttpSetOption(session.handle, _WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, unsafe.Pointer(&enableHttp), uint32(unsafe.Sizeof(enableHttp))) != nil {
		enableHttp = _WINHTTP_PROTOCOL_FLAG_HTTP2
		_ = winHttpSetOption(session.handle, _WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, unsafe.Pointer(&enableHttp), uint32(unsafe.Sizeof(enableHttp)))
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
	length, err = strconv.ParseUint(windows.UTF16ToString(numBuf[:numLen/2]), 10, 64)
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
		return
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
