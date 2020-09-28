/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// I wish we didn't have to do this. netiohlp.dll (what's used by netsh.exe) has some nice tricks with writing directly
// to the registry and the nsi kernel object, but it's not clear copying those makes for a stable interface. WMI doesn't
// work with v6. CMI isn't in Windows 7.
func runNetsh(cmds []string) error {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	cmd := exec.Command(filepath.Join(system32, "netsh.exe")) // I wish we could append (, "-f", "CONIN$") but Go sets up the process context wrong.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("runNetsh stdin pipe - %v", err)
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, strings.Join(append(cmds, "exit\r\n"), "\r\n"))
	}()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("runNetsh run - %v", err)
	}
	// Horrible kludges, sorry.
	cleaned := bytes.ReplaceAll(output, []byte("netsh>"), []byte{})
	cleaned = bytes.ReplaceAll(cleaned, []byte("There are no Domain Name Servers (DNS) configured on this computer."), []byte{})
	cleaned = bytes.TrimSpace(cleaned)
	if len(cleaned) != 0 {
		return fmt.Errorf("runNetsh returned error strings.\ninput:\n%s\noutput\n:%s",
			strings.Join(cmds, "\n"), bytes.ReplaceAll(output, []byte{'\r', '\n'}, []byte{'\n'}))
	}
	return nil
}
