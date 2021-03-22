/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

// import "golang.org/x/sys/windows/registry"

// const adminRegKey = `Software\WireGuard`

// var adminKey registry.Key

// func openAdminKey() (registry.Key, error) {
// 	if adminKey != 0 {
// 		return adminKey, nil
// 	}
// 	var err error
// 	adminKey, err = registry.OpenKey(registry.LOCAL_MACHINE, adminRegKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
// 	if err != nil {
// 		return 0, err
// 	}
// 	return adminKey, nil
// }

func AdminBool(name string) bool {

	switch name {
	case "MultipleSimultaneousTunnels":
		return false
	case "LimitedOperatorUI":
		return false
	case "DangerousScriptExecution":
		return false
	}

	return false

	// key, err := openAdminKey()
	// if err != nil {
	// 	return false
	// }
	// val, _, err := key.GetIntegerValue(name)
	// if err != nil {
	// 	return false
	// }
	// return val != 0
}
