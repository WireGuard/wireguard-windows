/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"encoding/asn1"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/version/wintrust"
)

const (
	officialCommonName = "WireGuard LLC"
	evPolicyOid        = "2.23.140.1.3"
	policyExtensionOid = "2.5.29.32"
)

type policyQualifierInfo struct {
	PolicyQualifierId asn1.ObjectIdentifier
	Qualifier         asn1.RawValue
}

type policyInformation struct {
	Policy     asn1.ObjectIdentifier
	Qualifiers []policyQualifierInfo `asn1:"optional"`
}

func VerifyAuthenticode(path string) bool {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	file := &wintrust.WinTrustFileInfo{
		CbStruct: uint32(unsafe.Sizeof(wintrust.WinTrustFileInfo{})),
		FilePath: path16,
	}
	data := &wintrust.WinTrustData{
		CbStruct:                        uint32(unsafe.Sizeof(wintrust.WinTrustData{})),
		UIChoice:                        wintrust.WTD_UI_NONE,
		RevocationChecks:                wintrust.WTD_REVOKE_WHOLECHAIN, // Full revocation checking, as this is called with network connectivity.
		UnionChoice:                     wintrust.WTD_CHOICE_FILE,
		StateAction:                     wintrust.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: uintptr(unsafe.Pointer(file)),
	}
	return wintrust.WinVerifyTrust(windows.InvalidHandle, &wintrust.WINTRUST_ACTION_GENERIC_VERIFY_V2, data) == nil
}

// This is an easily by-passable check, which doesn't serve a security purpose but mostly just a low-grade
// informational and semantic one.
func IsRunningOfficialVersion() bool {
	path, err := os.Executable()
	if err != nil {
		return false
	}

	// This is easily circumvented. We don't even verify the chain before hand with WinVerifyTrust.
	// False certificates can be appended. But that's okay, as this isn't security related.

	certs, err := wintrust.ExtractCertificates(path)
	if err != nil {
		return false
	}
	for _, cert := range certs {
		if cert.Subject.CommonName == officialCommonName {
			return true
		}
	}
	return false
}

func IsRunningEVSigned() bool {
	path, err := os.Executable()
	if err != nil {
		return false
	}

	// This is easily circumvented. We don't even verify the chain before hand with WinVerifyTrust.
	// False certificates can be appended. But that's okay, as this isn't security related.

	certs, err := wintrust.ExtractCertificates(path)
	if err != nil {
		return false
	}
	for _, cert := range certs {
		for _, extension := range cert.Extensions {
			if extension.Id.String() == policyExtensionOid {
				var policies []policyInformation
				if _, err = asn1.Unmarshal(extension.Value, &policies); err != nil {
					continue
				}
				for _, policy := range policies {
					if policy.Policy.String() == evPolicyOid {
						return true
					}
				}
			}
		}
	}
	return false
}
