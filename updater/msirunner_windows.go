/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
	"os"
	"os/exec"
	"path"
	"syscall"
)

func runMsi(msiPath string, userToken uintptr, env []string) error {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devNull.Close()
	attr := &os.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Token: syscall.Token(userToken),
		},
		Files: []*os.File{devNull, devNull, devNull},
		Env:   env,
		Dir:   path.Dir(msiPath),
	}
	proc, err := os.StartProcess(path.Join(system32, "msiexec.exe"), []string{"/qb!-", "/i", path.Base(msiPath)}, attr)
	if err != nil {
		return err
	}
	state, err := proc.Wait()
	if err != nil {
		return err
	}
	if !state.Success() {
		return &exec.ExitError{ProcessState: state}
	}
	return nil
}

func msiSaveDirectory(userToken uintptr) (string, error) {
	//TODO: BUG: XXX: There is a TOCTOU here, since this actually returns the unpriv'd users directory,
	// so in between saving the MSI and executing it, an attacker could swap it for a malicious one.
	root, err := conf.RootDirectoryForToken(windows.Token(userToken))
	if err != nil {
		return "", err
	}
	return path.Join(root, "Updates"), nil
}
