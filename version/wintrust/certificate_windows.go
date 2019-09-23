/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wintrust

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	_CERT_QUERY_OBJECT_FILE                     = 1
	_CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1024
	_CERT_QUERY_FORMAT_FLAG_ALL                 = 14
	_CERT_NAME_SIMPLE_DISPLAY_TYPE              = 4
)

//sys	cryptQueryObject(objectType uint32, object uintptr, expectedContentTypeFlags uint32, expectedFormatTypeFlags uint32, flags uint32, msgAndCertEncodingType *uint32, contentType *uint32, formatType *uint32, certStore *windows.Handle, msg *windows.Handle, context *uintptr) (err error) = crypt32.CryptQueryObject
//sys	certGetNameString(certContext *windows.CertContext, nameType uint32, flags uint32, typePara uintptr, name *uint16, size uint32) (chars uint32) = crypt32.CertGetNameStringW

func ExtractCertificateNames(path string) ([]string, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var certStore windows.Handle
	err = cryptQueryObject(_CERT_QUERY_OBJECT_FILE, uintptr(unsafe.Pointer(path16)), _CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, _CERT_QUERY_FORMAT_FLAG_ALL, 0, nil, nil, nil, &certStore, nil, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(certStore, 0)
	var cert *windows.CertContext
	var names []string
	for {
		cert, err = windows.CertEnumCertificatesInStore(certStore, cert)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == syscall.Errno(windows.CRYPT_E_NOT_FOUND) {
					break
				}
			}
			return nil, err
		}
		if cert == nil {
			break
		}
		nameLen := certGetNameString(cert, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, 0, nil, 0)
		if nameLen == 0 {
			continue
		}
		name16 := make([]uint16, nameLen)
		if certGetNameString(cert, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, 0, &name16[0], nameLen) != nameLen {
			continue
		}
		if name16[0] == 0 {
			continue
		}
		names = append(names, windows.UTF16ToString(name16))
	}
	if names == nil {
		return nil, syscall.Errno(windows.CRYPT_E_NOT_FOUND)
	}
	return names, nil
}
