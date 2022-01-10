/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 */

package driver

import (
	"log"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type loggerLevel int

const (
	logInfo loggerLevel = iota
	logWarn
	logErr
)

const AdapterNameMax = 128

type Adapter struct {
	handle           uintptr
	lastGetGuessSize uint32
}

var (
	modwireguard                         = newLazyDLL("wireguard.dll", setupLogger)
	procWireGuardCreateAdapter           = modwireguard.NewProc("WireGuardCreateAdapter")
	procWireGuardOpenAdapter             = modwireguard.NewProc("WireGuardOpenAdapter")
	procWireGuardCloseAdapter            = modwireguard.NewProc("WireGuardCloseAdapter")
	procWireGuardDeleteDriver            = modwireguard.NewProc("WireGuardDeleteDriver")
	procWireGuardGetAdapterLUID          = modwireguard.NewProc("WireGuardGetAdapterLUID")
	procWireGuardGetRunningDriverVersion = modwireguard.NewProc("WireGuardGetRunningDriverVersion")
	procWireGuardSetAdapterLogging       = modwireguard.NewProc("WireGuardSetAdapterLogging")
)

type TimestampedWriter interface {
	WriteWithTimestamp(p []byte, ts int64) (n int, err error)
}

func logMessage(level loggerLevel, timestamp uint64, msg *uint16) int {
	if tw, ok := log.Default().Writer().(TimestampedWriter); ok {
		tw.WriteWithTimestamp([]byte(log.Default().Prefix()+windows.UTF16PtrToString(msg)), (int64(timestamp)-116444736000000000)*100)
	} else {
		log.Println(windows.UTF16PtrToString(msg))
	}
	return 0
}

func setupLogger(dll *lazyDLL) {
	var callback uintptr
	if runtime.GOARCH == "386" {
		callback = windows.NewCallback(func(level loggerLevel, timestampLow, timestampHigh uint32, msg *uint16) int {
			return logMessage(level, uint64(timestampHigh)<<32|uint64(timestampLow), msg)
		})
	} else if runtime.GOARCH == "arm" {
		callback = windows.NewCallback(func(level loggerLevel, _, timestampLow, timestampHigh uint32, msg *uint16) int {
			return logMessage(level, uint64(timestampHigh)<<32|uint64(timestampLow), msg)
		})
	} else if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		callback = windows.NewCallback(logMessage)
	}
	syscall.SyscallN(dll.NewProc("WireGuardSetLogger").Addr(), callback)
}

func closeAdapter(wireguard *Adapter) {
	syscall.SyscallN(procWireGuardCloseAdapter.Addr(), wireguard.handle)
}

// CreateAdapter creates a WireGuard adapter. name is the cosmetic name of the adapter.
// tunnelType represents the type of adapter and should be "WireGuard". requestedGUID is
// the GUID of the created network adapter, which then influences NLA generation
// deterministically. If it is set to nil, the GUID is chosen by the system at random,
// and hence a new NLA entry is created for each new adapter.
func CreateAdapter(name, tunnelType string, requestedGUID *windows.GUID) (wireguard *Adapter, err error) {
	var name16 *uint16
	name16, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	var tunnelType16 *uint16
	tunnelType16, err = windows.UTF16PtrFromString(tunnelType)
	if err != nil {
		return
	}
	r0, _, e1 := syscall.SyscallN(procWireGuardCreateAdapter.Addr(), uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(tunnelType16)), uintptr(unsafe.Pointer(requestedGUID)))
	if r0 == 0 {
		err = e1
		return
	}
	wireguard = &Adapter{handle: r0}
	runtime.SetFinalizer(wireguard, closeAdapter)
	return
}

// OpenAdapter opens an existing WireGuard adapter by name.
func OpenAdapter(name string) (wireguard *Adapter, err error) {
	var name16 *uint16
	name16, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	r0, _, e1 := syscall.SyscallN(procWireGuardOpenAdapter.Addr(), uintptr(unsafe.Pointer(name16)))
	if r0 == 0 {
		err = e1
		return
	}
	wireguard = &Adapter{handle: r0}
	runtime.SetFinalizer(wireguard, closeAdapter)
	return
}

// Close closes a WireGuard adapter.
func (wireguard *Adapter) Close() (err error) {
	runtime.SetFinalizer(wireguard, nil)
	r1, _, e1 := syscall.SyscallN(procWireGuardCloseAdapter.Addr(), wireguard.handle)
	if r1 == 0 {
		err = e1
	}
	return
}

// Uninstall removes the driver from the system if no drivers are currently in use.
func Uninstall() (err error) {
	r1, _, e1 := syscall.SyscallN(procWireGuardDeleteDriver.Addr())
	if r1 == 0 {
		err = e1
	}
	return
}

type AdapterLogState uint32

const (
	AdapterLogOff          AdapterLogState = 0
	AdapterLogOn           AdapterLogState = 1
	AdapterLogOnWithPrefix AdapterLogState = 2
)

// SetLogging enables or disables logging on the WireGuard adapter.
func (wireguard *Adapter) SetLogging(logState AdapterLogState) (err error) {
	r1, _, e1 := syscall.SyscallN(procWireGuardSetAdapterLogging.Addr(), wireguard.handle, uintptr(logState))
	if r1 == 0 {
		err = e1
	}
	return
}

// RunningVersion returns the version of the loaded driver.
func RunningVersion() (version uint32, err error) {
	r0, _, e1 := syscall.SyscallN(procWireGuardGetRunningDriverVersion.Addr())
	version = uint32(r0)
	if version == 0 {
		err = e1
	}
	return
}

// LUID returns the LUID of the adapter.
func (wireguard *Adapter) LUID() (luid winipcfg.LUID) {
	syscall.SyscallN(procWireGuardGetAdapterLUID.Addr(), wireguard.handle, uintptr(unsafe.Pointer(&luid)))
	return
}
