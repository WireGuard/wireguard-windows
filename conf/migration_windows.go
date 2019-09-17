/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"log"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func maybeMigrate(c string) {
	vol := filepath.VolumeName(c)
	withoutVol := strings.TrimPrefix(c, vol)
	oldRoot := filepath.Join(vol, "\\windows.old")
	oldC := filepath.Join(oldRoot, withoutVol)

	sd, err := windows.GetNamedSecurityInfo(oldRoot, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err == windows.ERROR_PATH_NOT_FOUND || err == windows.ERROR_FILE_NOT_FOUND {
		return
	}
	if err != nil {
		log.Printf("Not migrating configuration from ‘%s’ due to GetNamedSecurityInfo error: %v", oldRoot, err)
		return
	}
	owner, defaulted, err := sd.Owner()
	if err != nil {
		log.Printf("Not migrating configuration from ‘%s’ due to GetSecurityDescriptorOwner error: %v", oldRoot, err)
		return
	}
	if defaulted || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		log.Printf("Not migrating configuration from ‘%s’, as it is not explicitly owned by SYSTEM, but rather ‘%v’", oldRoot, owner)
		return
	}
	err = windows.MoveFileEx(windows.StringToUTF16Ptr(oldC), windows.StringToUTF16Ptr(c), windows.MOVEFILE_COPY_ALLOWED)
	if err != nil {
		if err != windows.ERROR_FILE_NOT_FOUND && err != windows.ERROR_ALREADY_EXISTS {
			log.Printf("Not migrating configuration from ‘%s’ due to error when moving files: %v", oldRoot, err)
		}
		return
	}
	log.Printf("Migrated configuration from ‘%s’", oldRoot)
}
