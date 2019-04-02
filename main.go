/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/service"
	"golang.zx2c4.com/wireguard/windows/ui"
	"os"
	"strconv"
	"strings"
	"time"
)

var flags = [...]string{
	"(no argument): elevate and install manager service for current user",
	"/installmanagerservice",
	"/installtunnelservice CONFIG_PATH",
	"/uninstallmanagerservice",
	"/uninstalltunnelservice CONFIG_PATH",
	"/managerservice",
	"/tunnelservice CONFIG_PATH",
	"/ui CMD_READ_HANDLE CMD_WRITE_HANDLE CMD_EVENT_HANDLE LOG_MAPPING_HANDLE",
}

//sys messageBoxEx(hwnd windows.Handle, text *uint16, title *uint16, typ uint, languageId uint16) = user32.MessageBoxExW

func fatal(v ...interface{}) {
	messageBoxEx(0, windows.StringToUTF16Ptr(fmt.Sprint(v...)), windows.StringToUTF16Ptr("Error"), 0x00000010, 0)
}

func usage() {
	builder := strings.Builder{}
	for _, flag := range flags {
		builder.WriteString(fmt.Sprintf("    %s\n", flag))
	}
	msg := fmt.Sprintf("Usage: %s [\n%s]", os.Args[0], builder.String())
	messageBoxEx(0, windows.StringToUTF16Ptr(msg), windows.StringToUTF16Ptr("Command Line Options"), 0x00000040, 0)
	os.Exit(1)
}

//sys shellExecute(hwnd windows.Handle, verb *uint16, file *uint16, args *uint16, cwd *uint16, showCmd int) (err error) = shell32.ShellExecuteW
func execElevatedManagerServiceInstaller() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	err = shellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(path), windows.StringToUTF16Ptr("/installmanagerservice"), nil, windows.SW_SHOW)
	if err != nil {
		return err
	}
	os.Exit(0)
	return windows.ERROR_ACCESS_DENIED // Not reached
}

func pipeFromHandleArgument(handleStr string) (*os.File, error) {
	handleInt, err := strconv.ParseUint(handleStr, 10, 64)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handleInt), "pipe"), nil
}

func main() {
	if len(os.Args) <= 1 {
		if ui.RaiseUI() {
			return
		}
		err := execElevatedManagerServiceInstaller()
		if err != nil {
			fatal(err)
		}
		return
	}
	switch os.Args[1] {
	case "/installmanagerservice":
		if len(os.Args) != 2 {
			usage()
		}
		go ui.WaitForRaiseUIThenQuit()
		err := service.InstallManager()
		if err != nil {
			fatal(err)
		}
		time.Sleep(30 * time.Second)
		fatal("WireGuard system tray icon did not appear after 30 seconds.")
		return
	case "/uninstallmanagerservice":
		if len(os.Args) != 2 {
			usage()
		}
		err := service.UninstallManager()
		if err != nil {
			fatal(err)
		}
		return
	case "/managerservice":
		if len(os.Args) != 2 {
			usage()
		}
		err := service.RunManager()
		if err != nil {
			fatal(err)
		}
		return
	case "/installtunnelservice":
		if len(os.Args) != 3 {
			usage()
		}
		err := service.InstallTunnel(os.Args[2])
		if err != nil {
			fatal(err)
		}
		return
	case "/uninstalltunnelservice":
		if len(os.Args) != 3 {
			usage()
		}
		err := service.UninstallTunnel(os.Args[2])
		if err != nil {
			fatal(err)
		}
		return
	case "/tunnelservice":
		if len(os.Args) != 3 {
			usage()
		}
		err := service.RunTunnel(os.Args[2])
		if err != nil {
			fatal(err)
		}
		return
	case "/ui":
		if len(os.Args) != 6 {
			usage()
		}
		readPipe, err := pipeFromHandleArgument(os.Args[2])
		if err != nil {
			fatal(err)
		}
		writePipe, err := pipeFromHandleArgument(os.Args[3])
		if err != nil {
			fatal(err)
		}
		eventPipe, err := pipeFromHandleArgument(os.Args[4])
		if err != nil {
			fatal(err)
		}
		service.InitializeIPCClient(readPipe, writePipe, eventPipe)
		ui.RunUI()
		return
	}
	usage()
}
