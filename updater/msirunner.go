/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type tempFile struct {
	*os.File
	originalHandle windows.Handle
}

func (t *tempFile) ExclusivePath() string {
	if t.originalHandle != 0 {
		t.Close() // TODO: sort of a toctou, but msi requires unshared file
		t.originalHandle = 0
	}
	return t.Name()
}

func (t *tempFile) Delete() error {
	if t.originalHandle == 0 {
		name16, err := windows.UTF16PtrFromString(t.Name())
		if err != nil {
			return err
		}
		return windows.DeleteFile(name16) //TODO: how does this deal with reparse points?
	}
	disposition := byte(1)
	err := windows.SetFileInformationByHandle(t.originalHandle, windows.FileDispositionInfo, &disposition, 1)
	t.originalHandle = 0
	t.Close()
	return err
}

func runMsi(msi *tempFile, userToken uintptr) error {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devNull.Close()
	msiPath := msi.ExclusivePath()
	attr := &os.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Token: syscall.Token(userToken),
		},
		Files: []*os.File{devNull, devNull, devNull},
		Dir:   filepath.Dir(msiPath),
	}
	msiexec := filepath.Join(system32, "msiexec.exe")
	proc, err := os.StartProcess(msiexec, []string{msiexec, "/qb!-", "/i", filepath.Base(msiPath)}, attr)
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

func msiTempFile() (*tempFile, error) {
	var randBytes [32]byte
	n, err := rand.Read(randBytes[:])
	if err != nil {
		return nil, err
	}
	if n != int(len(randBytes)) {
		return nil, errors.New("Unable to generate random bytes")
	}
	sd, err := windows.SecurityDescriptorFromString("O:SYD:PAI(A;;FA;;;SY)(A;;FR;;;BA)")
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	windir, err := windows.GetWindowsDirectory()
	if err != nil {
		return nil, err
	}
	name := filepath.Join(windir, "Temp", hex.EncodeToString(randBytes[:]))
	name16 := windows.StringToUTF16Ptr(name)
	fileHandle, err := windows.CreateFile(name16, windows.GENERIC_WRITE|windows.DELETE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_TEMPORARY, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, err
	}
	windows.MoveFileEx(name16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	return &tempFile{
		File:           os.NewFile(uintptr(fileHandle), name),
		originalHandle: fileHandle,
	}, nil
}
