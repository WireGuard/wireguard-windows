/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

var cachedConfigFileDir string
var cachedRootDir string
var disableAutoMigration bool

// PresetRootDirectory causes RootDirectory() to not try any automatic deduction, and instead
// uses what's passed to it. This isn't used by wireguard-windows, but is useful for external
// consumers of our libraries who might want to do strange things.
func PresetRootDirectory(root string) {
	cachedRootDir = root
	disableAutoMigration = true
}
