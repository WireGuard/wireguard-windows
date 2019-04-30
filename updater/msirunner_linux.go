/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"fmt"
	"os/exec"
)

// This isn't a Linux program, yes, but having the updater package work across platforms is quite helpful for testing.

func runMsi(msiPath string) error {
	return exec.Command("qarma", "--info", "--text", fmt.Sprintf("It seems to be working! Were we on Windows, ‘%s’ would be executed.", msiPath)).Run()
}

func msiSaveDirectory() (string, error) {
	return "/tmp/wireguard-update-test-msi-directory", nil
}
