// +build arm

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package elevate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"golang.zx2c4.com/wireguard/windows/version"
)

const (
	releaseOffset                            = 2
	acquireModernLicenseWithPreviousIdOffset = 8
)

type shellExecuteBlock struct {
	shellExecuteSavedProgram   [260]uint16
	shellExecuteSavedArguments [260]uint16
	shellExecuteSavedDirectory [260]uint16
	shellExecuteShow           int32
}

var savedBlock = [unsafe.Sizeof(shellExecuteBlock{})]byte{0x00, 0xd2, 0xe3, 0xf7, 0xd3, 0x6a, 0x04, 0xb7, 0xa5, 0x6a, 0xb3, 0xaa, 0x1a, 0xb2, 0x25, 0x43}

func init() {
	if savedBlock[0] == 0 {
		return
	}
	var shellExecuteArgs = (*shellExecuteBlock)(unsafe.Pointer(&savedBlock[0]))

	var (
		program16   *uint16
		arguments16 *uint16
		directory16 *uint16
	)
	if shellExecuteArgs.shellExecuteSavedProgram[0] != 0 {
		program16 = &shellExecuteArgs.shellExecuteSavedProgram[0]
	}
	if shellExecuteArgs.shellExecuteSavedArguments[0] != 0 {
		directory16 = &shellExecuteArgs.shellExecuteSavedArguments[0]
	}
	if shellExecuteArgs.shellExecuteSavedDirectory[0] != 0 {
		arguments16 = &shellExecuteArgs.shellExecuteSavedDirectory[0]
	}
	err := windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), program16, arguments16, directory16, shellExecuteArgs.shellExecuteShow)
	exitCode := uint32(0)
	var sysError *syscall.Errno
	if err != nil {
		exitCode = 1
		if errors.As(err, sysError) {
			exitCode = uint32(*sysError)
		}
	}
	windows.ExitProcess(exitCode)
}

func ShellExecute(program string, arguments string, directory string, show int32) (err error) {
	if len(program) == 0 {
		return
	}
	defer func() {
		if err == nil {
			return
		}
		var (
			program16   *uint16
			arguments16 *uint16
			directory16 *uint16
		)
		if len(program) > 0 {
			program16, _ = windows.UTF16PtrFromString(program)
		}
		if len(arguments) > 0 {
			arguments16, _ = windows.UTF16PtrFromString(arguments)
		}
		if len(directory) > 0 {
			directory16, _ = windows.UTF16PtrFromString(directory)
		}
		err = windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), program16, arguments16, directory16, show)
	}()

	if !version.IsRunningEVSigned() {
		err = windows.ERROR_INSUFFICIENT_LOGON_INFO
		return
	}

	var processToken windows.Token
	err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken)
	if err != nil {
		return
	}
	defer processToken.Close()
	if processToken.IsElevated() {
		err = windows.ERROR_SUCCESS
		return
	}
	if !TokenIsElevatedOrElevatable(processToken) {
		err = windows.ERROR_ACCESS_DENIED
		return
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", registry.QUERY_VALUE)
	if err != nil {
		return
	}
	promptBehavior, _, err := key.GetIntegerValue("ConsentPromptBehaviorAdmin")
	key.Close()
	if err != nil {
		return
	}
	if uint32(promptBehavior) == 0 {
		err = windows.ERROR_SUCCESS
		return
	}
	if uint32(promptBehavior) != 5 {
		err = windows.ERROR_ACCESS_DENIED
		return
	}

	key, err = registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UAC\\COMAutoApprovalList", registry.QUERY_VALUE)
	if err == nil {
		var autoApproved uint64
		autoApproved, _, err = key.GetIntegerValue("{17CCA47D-DAE5-4E4A-AC42-CC54E28F334A}")
		key.Close()
		if err != nil {
			return
		}
		if uint32(autoApproved) == 0 {
			err = windows.ERROR_ACCESS_DENIED
			return
		}
	}

	self, _ := os.Executable()
	dataTableEntry, err := findCurrentDataTableEntry()
	if err != nil {
		return
	}
	windowsDirectory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return
	}
	originalPath := dataTableEntry.FullDllName.Buffer
	explorerPath := windows.StringToUTF16Ptr(filepath.Join(windowsDirectory, "explorer.exe"))
	rtlInitUnicodeString(&dataTableEntry.FullDllName, explorerPath)
	defer func() {
		rtlInitUnicodeString(&dataTableEntry.FullDllName, originalPath)
		runtime.KeepAlive(explorerPath)
	}()

	selfBytes, err := ioutil.ReadFile(self)
	if err != nil {
		return
	}
	marker := bytes.Index(selfBytes, savedBlock[:16])
	if marker == -1 {
		err = windows.ERROR_IMAGE_AT_DIFFERENT_BASE
		return
	}
	newBlock := (*shellExecuteBlock)(unsafe.Pointer(&selfBytes[marker]))
	copy(newBlock.shellExecuteSavedProgram[:], windows.StringToUTF16(program))
	copy(newBlock.shellExecuteSavedArguments[:], windows.StringToUTF16(arguments))
	copy(newBlock.shellExecuteSavedDirectory[:], windows.StringToUTF16(directory))
	newBlock.shellExecuteShow = show

	var randBytes [32]byte
	n, err := rand.Read(randBytes[:])
	if err != nil || n != len(randBytes) {
		panic(err)
	}
	workDir := filepath.Join(os.TempDir(), hex.EncodeToString(randBytes[:]))
	fakeSystem32 := filepath.Join(workDir, "system32")
	fakeClipup := filepath.Join(fakeSystem32, "clipup.exe")
	defer os.RemoveAll(workDir)
	err = os.MkdirAll(fakeSystem32, 0700)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(fakeClipup, selfBytes, 0600)
	if err != nil {
		return
	}

	key, err = registry.OpenKey(registry.CURRENT_USER, "Environment", registry.WRITE)
	if err != nil {
		return
	}
	defer key.Close()
	err = key.SetStringValue("windir", workDir)
	if err != nil {
		return
	}
	defer key.DeleteValue("windir")

	if err = coInitializeEx(0, cCOINIT_APARTMENTTHREADED); err == nil {
		defer coUninitialize()
	}

	var interfacePointer **[0xffff]uintptr
	if err = coGetObject(
		windows.StringToUTF16Ptr("Elevation:Administrator!new:{17CCA47D-DAE5-4E4A-AC42-CC54E28F334A}"),
		&cBIND_OPTS3{
			cbStruct:       uint32(unsafe.Sizeof(cBIND_OPTS3{})),
			dwClassContext: cCLSCTX_LOCAL_SERVER,
		},
		&windows.GUID{0xF2DCB80D, 0x0670, 0x44BC, [8]byte{0x90, 0x02, 0xCD, 0x18, 0x68, 0x87, 0x30, 0xAF}},
		&interfacePointer,
	); err != nil {
		return
	}

	defer syscall.Syscall((*interfacePointer)[releaseOffset], 1, uintptr(unsafe.Pointer(interfacePointer)), 0, 0)

	zero := [3]uint32{}
	syscall.Syscall((*interfacePointer)[acquireModernLicenseWithPreviousIdOffset], 3,
		uintptr(unsafe.Pointer(interfacePointer)),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(" "))),
		uintptr(unsafe.Pointer(&zero[0])),
	)
	return
}
