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

func IsOfficialPath(path string) bool {
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
		RevocationChecks:                wintrust.WTD_REVOKE_NONE,
		UnionChoice:                     wintrust.WTD_CHOICE_FILE,
		StateAction:                     wintrust.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: uintptr(unsafe.Pointer(file)),
	}
	err = wintrust.WinVerifyTrust(0, &wintrust.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if err != nil {
		return false
	}

	//TODO: check that the certificate actually belongs to us

	return true
}

func IsOfficial() bool {
	path, err := os.Executable()
	if err != nil {
		return false
	}
	return IsOfficialPath(path)
}
