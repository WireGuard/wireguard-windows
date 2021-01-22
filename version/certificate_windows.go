/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func extractCertificateNames(path string) ([]string, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var certStore windows.Handle
	err = windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(path16), windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_ALL, 0, nil, nil, nil, &certStore, nil, nil)
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
		nameLen := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
		if nameLen == 0 {
			continue
		}
		name16 := make([]uint16, nameLen)
		if windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name16[0], nameLen) != nameLen {
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

func extractCertificatePolicies(path string, oid string) ([]string, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	oid8, err := windows.BytePtrFromString(oid)
	if err != nil {
		return nil, err
	}
	var certStore windows.Handle
	err = windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(path16), windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_ALL, 0, nil, nil, nil, &certStore, nil, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(certStore, 0)
	var cert *windows.CertContext
	var policies []string
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
		ci := (*windows.CertInfo)(unsafe.Pointer(cert.CertInfo))
		ext := windows.CertFindExtension(oid8, ci.CountExtensions, ci.Extensions)
		if ext == nil {
			continue
		}
		var decodedLen uint32
		err = windows.CryptDecodeObject(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, ext.ObjId, ext.Value.Data, ext.Value.Size, 0, nil, &decodedLen)
		if err != nil {
			return nil, err
		}
		bytes := make([]byte, decodedLen)
		certPoliciesInfo := (*windows.CertPoliciesInfo)(unsafe.Pointer(&bytes[0]))
		err = windows.CryptDecodeObject(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, ext.ObjId, ext.Value.Data, ext.Value.Size, 0, unsafe.Pointer(&bytes[0]), &decodedLen)
		if err != nil {
			return nil, err
		}
		for i := uintptr(0); i < uintptr(certPoliciesInfo.Count); i++ {
			cp := (*windows.CertPolicy)(unsafe.Pointer(uintptr(unsafe.Pointer(certPoliciesInfo.PolicyInfos)) + i*unsafe.Sizeof(*certPoliciesInfo.PolicyInfos)))
			policies = append(policies, windows.BytePtrToString(cp.Identifier))
		}
	}
	if policies == nil {
		return nil, syscall.Errno(windows.CRYPT_E_NOT_FOUND)
	}
	return policies, nil
}
