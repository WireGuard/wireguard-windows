/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	officialCommonName = "WireGuard LLC"
	evPolicyOid        = "2.23.140.1.3"
	policyExtensionOid = "2.5.29.32"
)

func VerifyAuthenticode(path string) bool {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	data := &windows.WinTrustData{
		Size:                        uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_WHOLECHAIN, // Full revocation checking, as this is called with network connectivity.
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: path16,
		}),
	}
	return windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data) == nil
}

// These are easily by-passable checks, which do not serve serve security purposes. Do not place security-sensitive
// functions below this line.

func IsRunningOfficialVersion() bool {
	path, err := os.Executable()
	if err != nil {
		return false
	}

	names, err := extractCertificateNames(path)
	if err != nil {
		return false
	}
	for _, name := range names {
		if name == officialCommonName {
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

	policies, err := extractCertificatePolicies(path, policyExtensionOid)
	if err != nil {
		return false
	}
	for _, policy := range policies {
		if policy == evPolicyOid {
			return true
		}
	}
	return false
}
