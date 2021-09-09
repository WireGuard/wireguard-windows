/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

const adminRegKey = `Software\WireGuard`

var adminKey registry.Key

func openAdminKey() (registry.Key, error) {
	if adminKey != 0 {
		return adminKey, nil
	}
	var err error
	adminKey, err = registry.OpenKey(registry.LOCAL_MACHINE, adminRegKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, err
	}
	return adminKey, nil
}

func IsInsiderEnrolled() bool {
	if AdminBool("IgnoreInsiderProgram") {
		return false
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\WindowsSelfHost\Applicability`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	val, _, err := key.GetIntegerValue("IsBuildFlightingEnabled")
	if err != nil || val != 1 {
		return false
	}
	val, _, err = key.GetIntegerValue("EnablePreviewBuilds")
	if err != nil || val != 1 {
		return false
	}
	ring, _, err := key.GetStringValue("Ring")
	if err != nil || !strings.EqualFold(ring, "external") {
		return false
	}
	return true
}

func AdminBool(name string) bool {
	if name == "ExperimentalKernelDriver" && IsInsiderEnrolled() {
		return true
	}
	key, err := openAdminKey()
	if err != nil {
		return false
	}
	val, _, err := key.GetIntegerValue(name)
	if err != nil {
		return false
	}
	return val != 0
}

func SetAdminBool(name string, val bool) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, adminRegKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer key.Close()
	if val {
		return key.SetDWordValue(name, 1)
	} else {
		return key.DeleteValue(name)
	}
}
