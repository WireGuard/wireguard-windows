/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/conf"
)

func moveConfigsFromLegacyStore() {
	oldRoot, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return
	}
	oldC := filepath.Join(oldRoot, "WireGuard", "Configurations")
	files, err := os.ReadDir(oldC)
	if err != nil {
		return
	}
	pendingDeletion := make(map[string]bool)
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.READ); err == nil {
		if ntPaths, _, err := key.GetStringsValue("PendingFileRenameOperations"); err == nil {
			for _, ntPath := range ntPaths {
				pendingDeletion[strings.ToLower(strings.TrimPrefix(ntPath, `\??\`))] = true
			}
		}
		key.Close()
	}
	for i := range files {
		if files[i].IsDir() {
			continue
		}
		fileName := files[i].Name()
		oldPath := filepath.Join(oldC, fileName)
		if pendingDeletion[strings.ToLower(oldPath)] {
			continue
		}
		config, err := conf.LoadFromPath(oldPath)
		if err != nil {
			continue
		}
		newPath, err := config.Path()
		if err != nil {
			continue
		}
		err = config.Save(false)
		if err != nil {
			continue
		}
		oldPath16, err := windows.UTF16PtrFromString(oldPath)
		if err == nil {
			windows.MoveFileEx(oldPath16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
		}
		log.Printf("Migrated configuration from %#q to %#q", oldPath, newPath)
		changeTunnelServiceConfigFilePath(config.Name, oldPath, newPath)
	}
	oldC16, err := windows.UTF16PtrFromString(oldC)
	if err == nil {
		windows.MoveFileEx(oldC16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
	oldLog16, err := windows.UTF16PtrFromString(filepath.Join(oldRoot, "WireGuard", "log.bin"))
	if err == nil {
		windows.MoveFileEx(oldLog16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
	oldRoot16, err := windows.UTF16PtrFromString(filepath.Join(oldRoot, "WireGuard"))
	if err == nil {
		windows.MoveFileEx(oldRoot16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
}
