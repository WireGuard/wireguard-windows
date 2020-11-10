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

	"golang.zx2c4.com/wireguard/windows/conf"
)

func DumpTo(out io.Writer, notSystem bool) error {
	var path string
	if !notSystem {
		root, err := conf.RootDirectory()
		if err != nil {
			return err
		}
		path = filepath.Join(root, "log.bin")
	} else {
		root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
		if err != nil {
			return err
		}
		path = filepath.Join(root, "WireGuard", "log.bin")
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
