/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package driver

import (
	"errors"
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

const (
	PoolNameMax    = 256
	AdapterNameMax = 128
)

type Pool [PoolNameMax]uint16
type Adapter struct {
	handle           uintptr
	lastGetGuessSize uint32
}

var (
	modwireguard = newLazyDLL("wireguard.dll", setupLogger)

	procWireGuardCreateAdapter           = modwireguard.NewProc("WireGuardCreateAdapter")
	procWireGuardDeleteAdapter           = modwireguard.NewProc("WireGuardDeleteAdapter")
	procWireGuardDeletePoolDriver        = modwireguard.NewProc("WireGuardDeletePoolDriver")
	procWireGuardEnumAdapters            = modwireguard.NewProc("WireGuardEnumAdapters")
	procWireGuardFreeAdapter             = modwireguard.NewProc("WireGuardFreeAdapter")
	procWireGuardOpenAdapter             = modwireguard.NewProc("WireGuardOpenAdapter")
	procWireGuardGetAdapterLUID          = modwireguard.NewProc("WireGuardGetAdapterLUID")
	procWireGuardGetAdapterName          = modwireguard.NewProc("WireGuardGetAdapterName")
	procWireGuardGetRunningDriverVersion = modwireguard.NewProc("WireGuardGetRunningDriverVersion")
	procWireGuardSetAdapterName          = modwireguard.NewProc("WireGuardSetAdapterName")
	procWireGuardSetAdapterLogging       = modwireguard.NewProc("WireGuardSetAdapterLogging")
)

func setupLogger(dll *lazyDLL) {
	syscall.Syscall(dll.NewProc("WireGuardSetLogger").Addr(), 1, windows.NewCallback(func(level loggerLevel, timestamp uint64, msg *uint16) int {
		// TODO: Unfortunately, we're ignoring the precise timestamp here.
		log.Println(windows.UTF16PtrToString(msg))
		return 0
	}), 0, 0)
}

var DefaultPool, _ = MakePool("WireGuard")

func MakePool(poolName string) (pool *Pool, err error) {
	poolName16, err := windows.UTF16FromString(poolName)
	if err != nil {
		return
	}
	if len(poolName16) > PoolNameMax {
		err = errors.New("Pool name too long")
		return
	}
	pool = &Pool{}
	copy(pool[:], poolName16)
	return
}

func (pool *Pool) String() string {
	return windows.UTF16ToString(pool[:])
}

func freeAdapter(wireguard *Adapter) {
	syscall.Syscall(procWireGuardFreeAdapter.Addr(), 1, wireguard.handle, 0, 0)
}

// OpenAdapter finds a WireGuard adapter by its name. This function returns the adapter if found, or
// windows.ERROR_FILE_NOT_FOUND otherwise. If the adapter is found but not a WireGuard-class or a
// member of the pool, this function returns windows.ERROR_ALREADY_EXISTS. The adapter must be
// released after use.
func (pool *Pool) OpenAdapter(ifname string) (wireguard *Adapter, err error) {
	ifname16, err := windows.UTF16PtrFromString(ifname)
	if err != nil {
		return nil, err
	}
	r0, _, e1 := syscall.Syscall(procWireGuardOpenAdapter.Addr(), 2, uintptr(unsafe.Pointer(pool)), uintptr(unsafe.Pointer(ifname16)), 0)
	if r0 == 0 {
		err = e1
		return
	}
	wireguard = &Adapter{handle: r0}
	runtime.SetFinalizer(wireguard, freeAdapter)
	return
}

// CreateAdapter creates a WireGuard adapter. ifname is the requested name of the adapter, while
// requestedGUID is the GUID of the created network adapter, which then influences NLA generation
// deterministically. If it is set to nil, the GUID is chosen by the system at random, and hence a
// new NLA entry is created for each new adapter. It is called "requested" GUID because the API it
// uses is completely undocumented, and so there could be minor interesting complications with its
// usage. This function returns the network adapter ID and a flag if reboot is required.
func (pool *Pool) CreateAdapter(ifname string, requestedGUID *windows.GUID) (wireguard *Adapter, rebootRequired bool, err error) {
	var ifname16 *uint16
	ifname16, err = windows.UTF16PtrFromString(ifname)
	if err != nil {
		return
	}
	var _p0 uint32
	r0, _, e1 := syscall.Syscall6(procWireGuardCreateAdapter.Addr(), 4, uintptr(unsafe.Pointer(pool)), uintptr(unsafe.Pointer(ifname16)), uintptr(unsafe.Pointer(requestedGUID)), uintptr(unsafe.Pointer(&_p0)), 0, 0)
	rebootRequired = _p0 != 0
	if r0 == 0 {
		err = e1
		return
	}
	wireguard = &Adapter{handle: r0}
	runtime.SetFinalizer(wireguard, freeAdapter)
	return
}

// Delete deletes a WireGuard adapter. This function succeeds if the adapter was not found. It returns
// a bool indicating whether a reboot is required.
func (wireguard *Adapter) Delete() (rebootRequired bool, err error) {
	var _p0 uint32
	r1, _, e1 := syscall.Syscall(procWireGuardDeleteAdapter.Addr(), 2, wireguard.handle, uintptr(unsafe.Pointer(&_p0)), 0)
	rebootRequired = _p0 != 0
	if r1 == 0 {
		err = e1
	}
	return
}

// DeleteMatchingAdapters deletes all WireGuard adapters, which match
// given criteria, and returns which ones it deleted, whether a reboot
// is required after, and which errors occurred during the process.
func (pool *Pool) DeleteMatchingAdapters(matches func(adapter *Adapter) bool) (rebootRequired bool, errors []error) {
	cb := func(handle uintptr, _ uintptr) int {
		adapter := &Adapter{handle: handle}
		if !matches(adapter) {
			return 1
		}
		rebootRequired2, err := adapter.Delete()
		if err != nil {
			errors = append(errors, err)
			return 1
		}
		rebootRequired = rebootRequired || rebootRequired2
		return 1
	}
	r1, _, e1 := syscall.Syscall(procWireGuardEnumAdapters.Addr(), 3, uintptr(unsafe.Pointer(pool)), uintptr(windows.NewCallback(cb)), 0)
	if r1 == 0 {
		errors = append(errors, e1)
	}
	return
}

// Name returns the name of the WireGuard adapter.
func (wireguard *Adapter) Name() (ifname string, err error) {
	var ifname16 [AdapterNameMax]uint16
	r1, _, e1 := syscall.Syscall(procWireGuardGetAdapterName.Addr(), 2, wireguard.handle, uintptr(unsafe.Pointer(&ifname16[0])), 0)
	if r1 == 0 {
		err = e1
		return
	}
	ifname = windows.UTF16ToString(ifname16[:])
	return
}

// DeleteDriver deletes all WireGuard adapters in a pool and if there are no more adapters in any other
// pools, also removes WireGuard from the driver store, usually called by uninstallers.
func (pool *Pool) DeleteDriver() (rebootRequired bool, err error) {
	var _p0 uint32
	r1, _, e1 := syscall.Syscall(procWireGuardDeletePoolDriver.Addr(), 2, uintptr(unsafe.Pointer(pool)), uintptr(unsafe.Pointer(&_p0)), 0)
	rebootRequired = _p0 != 0
	if r1 == 0 {
		err = e1
	}
	return

}

// SetName sets name of the WireGuard adapter.
func (wireguard *Adapter) SetName(ifname string) (err error) {
	ifname16, err := windows.UTF16FromString(ifname)
	if err != nil {
		return err
	}
	r1, _, e1 := syscall.Syscall(procWireGuardSetAdapterName.Addr(), 2, wireguard.handle, uintptr(unsafe.Pointer(&ifname16[0])), 0)
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
	r1, _, e1 := syscall.Syscall(procWireGuardSetAdapterLogging.Addr(), 2, wireguard.handle, uintptr(logState), 0)
	if r1 == 0 {
		err = e1
	}
	return
}

// RunningVersion returns the version of the running WireGuard driver.
func RunningVersion() (version uint32, err error) {
	r0, _, e1 := syscall.Syscall(procWireGuardGetRunningDriverVersion.Addr(), 0, 0, 0, 0)
	version = uint32(r0)
	if version == 0 {
		err = e1
	}
	return
}

// LUID returns the LUID of the adapter.
func (wireguard *Adapter) LUID() (luid winipcfg.LUID) {
	syscall.Syscall(procWireGuardGetAdapterLUID.Addr(), 2, wireguard.handle, uintptr(unsafe.Pointer(&luid)), 0)
	return
}
