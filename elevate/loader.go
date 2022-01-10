/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package elevate

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

/* We could use the undocumented LdrFindEntryForAddress function instead, but that's undocumented, and we're trying
 * to be as rock-solid as possible here. */
func findCurrentDataTableEntry() (entry *windows.LDR_DATA_TABLE_ENTRY, err error) {
	peb := windows.RtlGetCurrentPeb()
	if peb == nil || peb.Ldr == nil {
		err = windows.ERROR_INVALID_ADDRESS
		return
	}
	for cur := peb.Ldr.InMemoryOrderModuleList.Flink; cur != &peb.Ldr.InMemoryOrderModuleList; cur = cur.Flink {
		entry = (*windows.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(cur)) - unsafe.Offsetof(windows.LDR_DATA_TABLE_ENTRY{}.InMemoryOrderLinks)))
		if entry.DllBase == peb.ImageBaseAddress {
			return
		}
	}
	entry = nil
	err = windows.ERROR_OBJECT_NOT_FOUND
	return
}
