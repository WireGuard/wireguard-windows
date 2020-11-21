/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/ipc"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func CopyConfigOwnerToIPCSecurityDescriptor(filename string) error {
	if conf.PathIsEncrypted(filename) {
		return nil
	}

	fileSd, err := windows.GetNamedSecurityInfo(filename, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	fileOwner, _, err := fileSd.Owner()
	if err != nil {
		return err
	}
	if fileOwner.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	additionalEntries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(fileOwner),
		},
	}}

	sd, err := ipc.UAPISecurityDescriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, defaulted, _ := sd.DACL()

	newDacl, err := windows.ACLFromEntries(additionalEntries, dacl)
	if err != nil {
		return err
	}
	err = sd.SetDACL(newDacl, true, defaulted)
	if err != nil {
		return err
	}
	sd, err = sd.ToSelfRelative()
	if err != nil {
		return err
	}
	ipc.UAPISecurityDescriptor = sd

	return nil
}
