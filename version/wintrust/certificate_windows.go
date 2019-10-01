/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wintrust

import (
	"crypto/x509"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	_CERT_QUERY_OBJECT_FILE                     = 1
	_CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1024
	_CERT_QUERY_FORMAT_FLAG_ALL                 = 14
)

//sys	cryptQueryObject(objectType uint32, object uintptr, expectedContentTypeFlags uint32, expectedFormatTypeFlags uint32, flags uint32, msgAndCertEncodingType *uint32, contentType *uint32, formatType *uint32, certStore *windows.Handle, msg *windows.Handle, context *uintptr) (err error) = crypt32.CryptQueryObject

func ExtractCertificates(path string) ([]x509.Certificate, error) {
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
	var certs []x509.Certificate
	var cert *windows.CertContext
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
		buf := make([]byte, cert.Length)
		copy(buf, (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:])
		if c, err := x509.ParseCertificate(buf); err == nil {
			certs = append(certs, *c)
		} else {
			return nil, err
		}
	}
	return certs, nil
}
