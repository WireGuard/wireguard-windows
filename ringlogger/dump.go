/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/version"
)

func DumpTo(out io.Writer, localSystem bool) error {
	var path string
	if !localSystem {
		root, err := conf.RootDirectory()
		if err != nil {
			return err
		}
		path = filepath.Join(root, "log.bin")
	} else {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-18", registry.QUERY_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()

		systemprofile, _, err := k.GetStringValue("ProfileImagePath")
		if err != nil {
			return err
		}
		systemprofile, err = registry.ExpandString(systemprofile)
		if err != nil {
			return err
		}
		name, _ := version.RunningNameVersion()
		path = filepath.Join(systemprofile, "AppData", "Local", name, "log.bin")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	mapping, err := windows.CreateFileMapping(windows.Handle(file.Fd()), nil, windows.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return err
	}
	rl, err := newRingloggerFromMappingHandle(mapping, "DMP", windows.FILE_MAP_READ)
	if err != nil {
		windows.CloseHandle(mapping)
		return err
	}
	defer rl.Close()
	_, err = rl.WriteTo(out)
	if err != nil {
		return err
	}
	return nil
}
