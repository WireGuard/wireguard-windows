/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"log"
	"path/filepath"

	"golang.zx2c4.com/wireguard/windows/conf"
)

var Global *Ringlogger

func InitGlobalLogger(tag string) error {
	if Global != nil {
		return nil
	}
	root, err := conf.RootDirectory()
	if err != nil {
		return err
	}
	Global, err = NewRinglogger(filepath.Join(root, "log.bin"), tag)
	if err != nil {
		return err
	}
	log.SetOutput(Global)
	log.SetFlags(0)
	return nil
}
