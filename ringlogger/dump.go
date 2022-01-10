/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func DumpTo(inPath string, out io.Writer, continuous bool) error {
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
	if !continuous {
		_, err = rl.WriteTo(out)
		if err != nil {
			return err
		}
	} else {
		cursor := CursorAll
		for {
			var items []FollowLine
			items, cursor = rl.FollowFromCursor(cursor)
			for _, item := range items {
				_, err = fmt.Fprintf(out, "%s: %s\n", item.Stamp.Format("2006-01-02 15:04:05.000000"), item.Line)
				if errors.Is(err, io.EOF) {
					return nil
				} else if err != nil {
					return err
				}
			}
			time.Sleep(time.Millisecond * 100)
		}
	}
	return nil
}
