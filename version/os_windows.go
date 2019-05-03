/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"fmt"
	"unsafe"
)

type OsVersionInfo struct {
	osVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CsdVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       byte
	reserved          byte
}

//sys rtlGetVersion(versionInfo *OsVersionInfo) (err error) [failretval!=0] = ntdll.RtlGetVersion

func OsVersion() (versionInfo OsVersionInfo, err error) {
	versionInfo.osVersionInfoSize = uint32(unsafe.Sizeof(versionInfo))
	err = rtlGetVersion(&versionInfo)
	return
}

func OsName() string {
	versionInfo, err := OsVersion()
	if err != nil {
		return "Windows Unknown"
	}
	winType := ""
	switch versionInfo.ProductType {
	case 3:
		winType = " Server"
	case 2:
		winType = " Controller"
	}
	return fmt.Sprintf("Windows%s %d.%d.%d", winType, versionInfo.MajorVersion, versionInfo.MinorVersion, versionInfo.BuildNumber)
}
