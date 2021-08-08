/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

func DumpTo(inPath string, out io.Writer) error {
	file, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer file.Close()
	mapping, err := windows.CreateFileMapping(windows.Handle(file.Fd()), nil, windows.PAGE_READONLY, 0, 0, nil)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
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
