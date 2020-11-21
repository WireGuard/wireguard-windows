/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func runScriptCommand(command, interfaceName string) error {
	if len(command) == 0 {
		return nil
	}
	if !conf.AdminBool("DangerousScriptExecution") {
		log.Printf("Skipping execution of script, because dangerous script execution is safely disabled: %#q", command)
		return nil
	}
	command = strings.ReplaceAll(command, "%i", interfaceName)
	log.Printf("Executing: %#q", command)
	comspec, _ := os.LookupEnv("COMSPEC")
	if len(comspec) == 0 {
		system32, err := windows.GetSystemDirectory()
		if err != nil {
			return err
		}
		comspec = filepath.Join(system32, "cmd.exe")
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devNull.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	process, err := os.StartProcess(comspec, nil /* CmdLine below */, &os.ProcAttr{
		Files: []*os.File{devNull, writer, writer},
		Sys: &syscall.SysProcAttr{
			HideWindow: true,
			CmdLine:    fmt.Sprintf("cmd /c %s", command),
		},
	})
	writer.Close()
	if err != nil {
		reader.Close()
		return err
	}
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			log.Printf("cmd> %s", scanner.Text())
		}
	}()
	state, err := process.Wait()
	reader.Close()
	if err != nil {
		return err
	}
	if state.ExitCode() == 0 {
		return nil
	}
	log.Printf("Command error exit status: %d", state.ExitCode())
	return windows.ERROR_GENERIC_COMMAND_FAILED
}
