/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/ui"
)

var flags = [...]string{
	"(no argument): elevate and install manager service for current user",
	"/installmanagerservice",
	"/installtunnelservice CONFIG_PATH",
	"/uninstallmanagerservice",
	"/uninstalltunnelservice TUNNEL_NAME",
	"/managerservice",
	"/tunnelservice CONFIG_PATH",
	"/ui CMD_READ_HANDLE CMD_WRITE_HANDLE CMD_EVENT_HANDLE LOG_MAPPING_HANDLE",
	"/dumplog OUTPUT_PATH",
}

func fatal(v ...interface{}) {
	windows.MessageBox(0, windows.StringToUTF16Ptr(fmt.Sprint(v...)), windows.StringToUTF16Ptr("Error"), windows.MB_ICONERROR)
	os.Exit(1)
}

func usage() {
	builder := strings.Builder{}
	for _, flag := range flags {
		builder.WriteString(fmt.Sprintf("    %s\n", flag))
	}
	msg := fmt.Sprintf("Usage: %s [\n%s]", os.Args[0], builder.String())
	windows.MessageBox(0, windows.StringToUTF16Ptr(msg), windows.StringToUTF16Ptr("Command Line Options"), windows.MB_ICONINFORMATION)
	os.Exit(1)
}

func checkForWow64() {
	var b bool
	p, err := windows.GetCurrentProcess()
	if err != nil {
		fatal(err)
	}
	err = windows.IsWow64Process(p, &b)
	if err != nil {
		fatal("Unable to determine whether the process is running under WOW64: ", err)
	}
	if b {
		fatal("You must use the 64-bit version of WireGuard on this computer.")
	}
}

func checkForAdminGroup() {
	// This is not a security check, but rather a user-confusion one.
	processToken, err := windows.OpenCurrentProcessToken()
	if err != nil {
		fatal("Unable to open current process token: ", err)
	}
	defer processToken.Close()
	if !services.TokenIsMemberOfBuiltInAdministrator(processToken) {
		fatal("WireGuard may only be used by users who are a member of the Builtin Administrators group.")
	}
}

func execElevatedManagerServiceInstaller() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	err = windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(path), windows.StringToUTF16Ptr("/installmanagerservice"), nil, windows.SW_SHOW)
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
	checkForWow64()

	if len(os.Args) <= 1 {
		checkForAdminGroup()
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
		err := manager.InstallManager()
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
		err := manager.UninstallManager()
		if err != nil {
			fatal(err)
		}
		return
	case "/managerservice":
		if len(os.Args) != 2 {
			usage()
		}
		err := manager.RunManager()
		if err != nil {
			fatal(err)
		}
		return
	case "/installtunnelservice":
		if len(os.Args) != 3 {
			usage()
		}
		err := manager.InstallTunnel(os.Args[2])
		if err != nil {
			fatal(err)
		}
		return
	case "/uninstalltunnelservice":
		if len(os.Args) != 3 {
			usage()
		}
		err := manager.UninstallTunnel(os.Args[2])
		if err != nil {
			fatal(err)
		}
		return
	case "/tunnelservice":
		if len(os.Args) != 3 {
			usage()
		}
		err := manager.RunTunnel(os.Args[2])
		if err != nil {
			fatal(err)
		}
		return
	case "/ui":
		if len(os.Args) != 6 {
			usage()
		}
		err := services.DropAllPrivileges(false)
		if err != nil {
			fatal(err)
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
		ringlogger.Global, err = ringlogger.NewRingloggerFromInheritedMappingHandle(os.Args[5], "GUI")
		if err != nil {
			fatal(err)
		}
		manager.InitializeIPCClient(readPipe, writePipe, eventPipe)
		ui.RunUI()
		return
	case "/dumplog":
		if len(os.Args) != 3 {
			usage()
		}
		file, err := os.Create(os.Args[2])
		if err != nil {
			fatal(err)
		}
		defer file.Close()
		err = ringlogger.DumpTo(file, true)
		if err != nil {
			fatal(err)
		}
		return
	}
	usage()
}
