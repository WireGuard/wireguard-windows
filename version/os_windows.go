/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"fmt"
	"unsafe"
)

type osVersionInfo struct {
	osVersionInfoSize uint32
	majorVersion      uint32
	minorVersion      uint32
	buildNumber       uint32
	platformId        uint32
	csdVersion        [128]uint16
	servicePackMajor  uint16
	servicePackMinor  uint16
	suiteMask         uint16
	productType       byte
	reserved          byte
}

//sys rtlGetVersion(versionInfo *osVersionInfo) (nterr uint32) = ntdll.RtlGetVersion

func OsName() string {
	windowsVersion := "Windows Unknown"
	versionInfo := &osVersionInfo{osVersionInfoSize: uint32(unsafe.Sizeof(osVersionInfo{}))}
	if rtlGetVersion(versionInfo) == 0 {
		winType := ""
		switch versionInfo.productType {
		case 3:
			winType = " Server"
		case 2:
			winType = " Controller"
		}
		windowsVersion = fmt.Sprintf("Windows%s %d.%d.%d", winType, versionInfo.majorVersion, versionInfo.minorVersion, versionInfo.buildNumber)
	}
	return windowsVersion
}
