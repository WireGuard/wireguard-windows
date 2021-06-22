/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"errors"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type uiProcess struct {
	handle uintptr
}

func launchUIProcess(executable string, args []string, workingDirectory string, handles []windows.Handle, token windows.Token) (*uiProcess, error) {
	executable16, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, err
	}
	args16, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return nil, err
	}
	workingDirectory16, err := windows.UTF16PtrFromString(workingDirectory)
	if err != nil {
		return nil, err
	}
	var environmentBlock *uint16
	err = windows.CreateEnvironmentBlock(&environmentBlock, token, false)
	if err != nil {
		return nil, err
	}
	defer windows.DestroyEnvironmentBlock(environmentBlock)
	attributeList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, err
	}
	defer attributeList.Delete()
	si := &windows.StartupInfoEx{
		StartupInfo:             windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{}))},
		ProcThreadAttributeList: attributeList.List(),
	}
	if len(handles) == 0 {
		handles = []windows.Handle{0}
	}
	attributeList.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0]))
	pi := new(windows.ProcessInformation)
	err = windows.CreateProcessAsUser(token, executable16, args16, nil, nil, true, windows.CREATE_DEFAULT_ERROR_MODE|windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT, environmentBlock, workingDirectory16, &si.StartupInfo, pi)
	if err != nil {
		return nil, err
	}
	windows.CloseHandle(pi.Thread)
	uiProc := &uiProcess{handle: uintptr(pi.Process)}
	runtime.SetFinalizer(uiProc, (*uiProcess).release)
	return uiProc, nil
}

func (p *uiProcess) release() error {
	handle := windows.Handle(atomic.SwapUintptr(&p.handle, uintptr(windows.InvalidHandle)))
	if handle == windows.InvalidHandle {
		return nil
	}
	err := windows.CloseHandle(handle)
	if err != nil {
		return err
	}
	runtime.SetFinalizer(p, nil)
	return nil
}

func (p *uiProcess) Wait() (uint32, error) {
	handle := windows.Handle(atomic.LoadUintptr(&p.handle))
	s, err := windows.WaitForSingleObject(handle, syscall.INFINITE)
	switch s {
	case windows.WAIT_OBJECT_0:
	case windows.WAIT_FAILED:
		return 0, err
	default:
		return 0, errors.New("unexpected result from WaitForSingleObject")
	}
	var exitCode uint32
	err = windows.GetExitCodeProcess(handle, &exitCode)
	if err != nil {
		return 0, err
	}
	p.release()
	return exitCode, nil
}

func (p *uiProcess) Kill() error {
	handle := windows.Handle(atomic.LoadUintptr(&p.handle))
	if handle == windows.InvalidHandle {
		return nil
	}
	return windows.TerminateProcess(handle, 1)
}
