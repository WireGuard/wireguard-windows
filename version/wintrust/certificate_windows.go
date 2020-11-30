/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
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

type blob struct {
	len  uint32
	data *byte
}

type bitBlob struct {
	len        uint32
	data       *byte
	unusedBits uint32
}

type algoIdentifier struct {
	objId  uintptr
	params blob
}

type pubkeyInfo struct {
	algo      algoIdentifier
	publicKey bitBlob
}

type certExtension struct {
	objId    *byte
	critical uint32
	value    blob
}

type certInfo struct {
	version              uint32
	serialNumber         blob           /* CRYPT_INTEGER_BLOB */
	signatureAlgorithm   algoIdentifier /* CRYPT_ALGORITHM_IDENTIFIER */
	issuer               blob           /* CERT_NAME_BLOB */
	notbefore            windows.Filetime
	notafter             windows.Filetime
	subject              blob       /* CERT_NAME_BLOB */
	subjectPublicKeyInfo pubkeyInfo /* CERT_PUBLIC_KEY_INFO */
	issuerUniqueId       bitBlob    /* CRYPT_BIT_BLOB */
	subjectUniqueId      bitBlob    /* CRYPT_BIT_BLOB */
	countExtensions      uint32
	extensions           *certExtension /* *CERT_EXTENSION */
}

type certPolicy struct {
	identifier      *byte
	countQualifiers uint32
	qualifiers      uintptr /* CERT_POLICY_QUALIFIER_INFO */
}

type certPoliciesInfo struct {
	countPolicyInfos uint32
	policyInfos      *certPolicy
}

//sys	cryptQueryObject(objectType uint32, object uintptr, expectedContentTypeFlags uint32, expectedFormatTypeFlags uint32, flags uint32, msgAndCertEncodingType *uint32, contentType *uint32, formatType *uint32, certStore *windows.Handle, msg *windows.Handle, context *uintptr) (err error) = crypt32.CryptQueryObject
//sys	certGetNameString(certContext *windows.CertContext, nameType uint32, flags uint32, typePara unsafe.Pointer, name *uint16, size uint32) (chars uint32) = crypt32.CertGetNameStringW
//sys	certFindExtension(objId *byte, countExtensions uint32, extensions *certExtension) (ret *certExtension) = crypt32.CertFindExtension
//sys	cryptDecodeObject(encodingType uint32, structType *byte, encodedBytes *byte, lenEncodedBytes uint32, flags uint32, decoded unsafe.Pointer, decodedLen *uint32) (err error) = crypt32.CryptDecodeObject

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
		nameLen := certGetNameString(cert, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
		if nameLen == 0 {
			continue
		}
		name16 := make([]uint16, nameLen)
		if certGetNameString(cert, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name16[0], nameLen) != nameLen {
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

func ExtractCertificatePolicies(path string, oid string) ([]string, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	oid8, err := windows.BytePtrFromString(oid)
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
		ci := (*certInfo)(unsafe.Pointer(cert.CertInfo))
		ext := certFindExtension(oid8, ci.countExtensions, ci.extensions)
		if ext == nil {
			continue
		}
		var decodedLen uint32
		err = cryptDecodeObject(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, ext.objId, ext.value.data, ext.value.len, 0, nil, &decodedLen)
		if err != nil {
			return nil, err
		}
		bytes := make([]byte, decodedLen)
		certPoliciesInfo := (*certPoliciesInfo)(unsafe.Pointer(&bytes[0]))
		err = cryptDecodeObject(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, ext.objId, ext.value.data, ext.value.len, 0, unsafe.Pointer(&bytes[0]), &decodedLen)
		if err != nil {
			return nil, err
		}
		for i := uintptr(0); i < uintptr(certPoliciesInfo.countPolicyInfos); i++ {
			cp := (*certPolicy)(unsafe.Pointer(uintptr(unsafe.Pointer(certPoliciesInfo.policyInfos)) + i*unsafe.Sizeof(*certPoliciesInfo.policyInfos)))
			policies = append(policies, windows.BytePtrToString(cp.identifier))
		}
	}
	if policies == nil {
		return nil, syscall.Errno(windows.CRYPT_E_NOT_FOUND)
	}
	return policies, nil
}
