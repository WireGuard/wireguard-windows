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

//sys	getFileSecurity(fileName *uint16, securityInformation uint32, securityDescriptor *byte, descriptorLen uint32, requestedLen *uint32) (err error) = advapi32.GetFileSecurityW
//sys	getSecurityDescriptorOwner(securityDescriptor *byte, sid **windows.SID, ownerDefaulted *bool) (err error) = advapi32.GetSecurityDescriptorOwner
const ownerSecurityInformation = 0x00000001

func maybeMigrate(c string) {
	vol := filepath.VolumeName(c)
	withoutVol := strings.TrimPrefix(c, vol)
	oldRoot := filepath.Join(vol, "\\windows.old")
	oldC := filepath.Join(oldRoot, withoutVol)

	var err error
	var sd []byte
	reqLen := uint32(128)
	for {
		sd = make([]byte, reqLen)
		//XXX: Since this takes a file path, it's technically a TOCTOU.
		err = getFileSecurity(windows.StringToUTF16Ptr(oldRoot), ownerSecurityInformation, &sd[0], uint32(len(sd)), &reqLen)
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			break
		}
	}
	if err == windows.ERROR_PATH_NOT_FOUND || err == windows.ERROR_FILE_NOT_FOUND {
		return
	}
	if err != nil {
		log.Printf("Not migrating configuration from '%s' due to GetFileSecurity error: %v", oldRoot, err)
		return
	}
	var defaulted bool
	var sid *windows.SID
	err = getSecurityDescriptorOwner(&sd[0], &sid, &defaulted)
	if err != nil {
		log.Printf("Not migrating configuration from '%s' due to GetSecurityDescriptorOwner error: %v", oldRoot, err)
		return
	}
	if defaulted || !sid.IsWellKnown(windows.WinLocalSystemSid) {
		sidStr, _ := sid.String()
		log.Printf("Not migrating configuration from '%s', as it is not explicitly owned by SYSTEM, but rather '%s'", oldRoot, sidStr)
		return
	}
	err = windows.MoveFileEx(windows.StringToUTF16Ptr(oldC), windows.StringToUTF16Ptr(c), windows.MOVEFILE_COPY_ALLOWED)
	if err != nil {
		if err != windows.ERROR_FILE_NOT_FOUND && err != windows.ERROR_ALREADY_EXISTS {
			log.Printf("Not migrating configuration from '%s' due to error when moving files: %v", oldRoot, err)
		}
		return
	}
	log.Printf("Migrated configuration from '%s'", oldRoot)
}
