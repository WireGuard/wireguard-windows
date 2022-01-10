/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package driver

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

func UninstallLegacyWintun() error {
	deviceClassNetGUID := &windows.GUID{0x4d36e972, 0xe325, 0x11ce, [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
	devInfo, err := windows.SetupDiCreateDeviceInfoListEx(deviceClassNetGUID, 0, "")
	if err != nil {
		return err
	}
	defer devInfo.Close()
	devInfoData, err := devInfo.CreateDeviceInfo("Wintun", deviceClassNetGUID, "", 0, windows.DICD_GENERATE_ID)
	if err != nil {
		return err
	}
	err = devInfo.SetDeviceRegistryProperty(devInfoData, windows.SPDRP_HARDWAREID, []byte("W\x00i\x00n\x00t\x00u\x00n\x00\x00\x00\x00\x00"))
	if err != nil {
		return err
	}
	err = devInfo.BuildDriverInfoList(devInfoData, windows.SPDIT_COMPATDRIVER)
	if err != nil {
		return err
	}
	defer devInfo.DestroyDriverInfoList(devInfoData, windows.SPDIT_COMPATDRIVER)
	var lastError error
	for i := 0; ; i++ {
		drvInfoData, err := devInfo.EnumDriverInfo(devInfoData, windows.SPDIT_COMPATDRIVER, i)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}
		drvInfoDetailData, err := devInfo.DriverInfoDetail(devInfoData, drvInfoData)
		if err != nil {
			continue
		}
		lastError = windows.SetupUninstallOEMInf(filepath.Base(drvInfoDetailData.InfFileName()), 0)
	}
	return lastError
}
