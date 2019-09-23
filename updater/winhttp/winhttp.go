/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package winhttp

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Response struct {
	session    _HINTERNET
	connection _HINTERNET
	request    _HINTERNET
}

func convertError(err *error) {
	if *err == nil {
		return
	}
	if se, ok := (*err).(syscall.Errno); ok {
		if se > _WINHTTP_ERROR_BASE && se <= _WINHTTP_ERROR_LAST {
			*err = Error(se)
		}
	}
}

func Get(userAgent string, url string) (response *Response, err error) {
	response = new(Response)
	defer convertError(&err)
	defer func() {
		if err != nil {
			response.Close()
			response = nil
		}
	}()
	userAgent16, err := windows.UTF16PtrFromString(userAgent)
	if err != nil {
		return
	}
	url16, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return
	}
	components := _URL_COMPONENTS{
		structSize:     uint32(unsafe.Sizeof(_URL_COMPONENTS{})),
		hostName:       &make([]uint16, 512)[0],
		hostNameLength: 512,
		urlPath:        &make([]uint16, 512)[0],
		urlPathLength:  512,
	}
	err = winHttpCrackUrl(url16, 0, _ICU_REJECT_USERPWD, &components)
	if err != nil {
		return
	}
	if components.schemeType != _INTERNET_SCHEME_HTTP && components.schemeType != _INTERNET_SCHEME_HTTPS {
		err = _ERROR_WINHTTP_INVALID_URL
		return
	}
	response.session, err = winHttpOpen(userAgent16, _WINHTTP_ACCESS_TYPE_NO_PROXY, nil, nil, 0)
	if err != nil {
		return
	}
	response.connection, err = winHttpConnect(response.session, components.hostName, components.port, 0)
	if err != nil {
		return
	}
	flags := uint32(_WINHTTP_FLAG_REFRESH)
	if components.schemeType == _INTERNET_SCHEME_HTTPS {
		flags |= _WINHTTP_FLAG_SECURE
	}
	response.request, err = winHttpOpenRequest(response.connection, windows.StringToUTF16Ptr("GET"), components.urlPath, nil, nil, nil, flags)
	if err != nil {
		return
	}
	err = winHttpSendRequest(response.request, nil, 0, nil, 0, 0, 0)
	if err != nil {
		return
	}
	err = winHttpReceiveResponse(response.request, 0)
	if err != nil {
		return
	}
	return
}

func (response *Response) Length() (length uint64, err error) {
	defer convertError(&err)
	numBuf := make([]uint16, 22)
	numLen := uint32(len(numBuf) * 2)
	err = winHttpQueryHeaders(response.request, _WINHTTP_QUERY_CONTENT_LENGTH, nil, unsafe.Pointer(&numBuf[0]), &numLen, nil)
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
	err = winHttpReadData(response.request, &p[0], uint32(len(p)), &bytesRead)
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
	var err1, err2, err3 error
	if response.request != 0 {
		err1 = winHttpCloseHandle(response.request)
	}
	if response.connection != 0 {
		err2 = winHttpCloseHandle(response.connection)
	}
	if response.session != 0 {
		err3 = winHttpCloseHandle(response.session)
	}
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	case err3 != nil:
		return err3
	}
	return nil
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
