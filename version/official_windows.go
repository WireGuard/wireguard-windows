/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/version/wintrust"
	"os"
	"unsafe"
)

const (
	officialCommonName = "WireGuard LLC"
)

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
	return wintrust.WinVerifyTrust(0, &wintrust.WINTRUST_ACTION_GENERIC_VERIFY_V2, data) == nil
}

// This is an easily by-passable check, which doesn't serve a security purpose but mostly just a low-grade
// informational and semantic one.
func IsRunningOfficialVersion() bool {
	path, err := os.Executable()
	if err != nil {
		return false
	}
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
		RevocationChecks:                wintrust.WTD_REVOKE_NONE, // No revocation, as this isn't security related.
		UnionChoice:                     wintrust.WTD_CHOICE_FILE,
		StateAction:                     wintrust.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: uintptr(unsafe.Pointer(file)),
	}
	err = wintrust.WinVerifyTrust(0, &wintrust.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if err != nil {
		return false
	}

	// This below tests is easily circumvented. False certificates can be appended, and just checking the
	// common name is not very good. But that's okay, as this isn't security related.
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
