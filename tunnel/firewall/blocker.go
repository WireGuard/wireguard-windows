/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

//
// Fundamental WireGuard specific WFP objects.
//
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

var wfpSession uintptr

func createWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("WireGuard", "WireGuard dynamic session")
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}

	sessionHandle := uintptr(0)

	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	// {48E29F38-7492-4436-8F92-29D78A8D29D3}
	providerGUID := windows.GUID{
		Data1: 0x48e29f38,
		Data2: 0x7492,
		Data3: 0x4436,
		Data4: [8]byte{0x8f, 0x92, 0x29, 0xd7, 0x8a, 0x8d, 0x29, 0xd3},
	}
	// {FE3DB7F8-4658-4DE5-8DA9-CE5086A8266B}
	filtersGUID := windows.GUID{
		Data1: 0xfe3db7f8,
		Data2: 0x4658,
		Data3: 0x4de5,
		Data4: [8]byte{0x8d, 0xa9, 0xce, 0x50, 0x86, 0xa8, 0x26, 0x6b},
	}

	//
	// Register provider.
	//
	{
		displayData, err := createWtFwpmDisplayData0("WireGuard", "The WireGuard provider")
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: providerGUID,
			displayData: *displayData,
		}
		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			//TODO: cleanup entire call chain of these if failure?
			return nil, wrapErr(err)
		}
	}

	//
	// Register filters sublayer.
	//
	{
		displayData, err := createWtFwpmDisplayData0("WireGuard filters", "Permissive and blocking filters")
		if err != nil {
			return nil, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: filtersGUID,
			displayData: *displayData,
			providerKey: &providerGUID,
			weight:      ^uint16(0),
		}
		err = fwpmSubLayerAdd0(session, &sublayer, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	return &baseObjects{
		providerGUID,
		filtersGUID,
	}, nil
}

func EnableFirewall(luid uint64, restrictToDNSServers []net.IP, restrictAll bool) error {
	if wfpSession != 0 {
		return errors.New("The firewall has already been enabled")
	}

	session, err := createWfpSession()
	if err != nil {
		return wrapErr(err)
	}

	objectInstaller := func(session uintptr) error {
		baseObjects, err := registerBaseObjects(session)
		if err != nil {
			return wrapErr(err)
		}

		if len(restrictToDNSServers) > 0 {
			err = blockDNS(restrictToDNSServers, session, baseObjects, 15, 14)
			if err != nil {
				return wrapErr(err)
			}
		}

		if restrictAll {
			err = permitLoopback(session, baseObjects, 13)
			if err != nil {
				return wrapErr(err)
			}
		}

		err = permitTunInterface(session, baseObjects, 12, luid)
		if err != nil {
			return wrapErr(err)
		}

		err = permitWireGuardService(session, baseObjects, 12)
		if err != nil {
			return wrapErr(err)
		}

		if restrictAll {
			err = permitDHCPIPv4(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			err = permitDHCPIPv6(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			err = permitNdp(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			/* TODO: actually evaluate if this does anything and if we need this. It's layer 2; our other rules are layer 3.
			 *  In other words, if somebody complains, try enabling it. For now, keep it off.
			err = permitHyperV(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}
			*/
		}

		if restrictAll {
			err = blockAll(session, baseObjects, 0)
			if err != nil {
				return wrapErr(err)
			}
		}

		return nil
	}

	err = runTransaction(session, objectInstaller)
	if err != nil {
		fwpmEngineClose0(session)
		return wrapErr(err)
	}

	wfpSession = session
	return nil
}

func DisableFirewall() {
	if wfpSession != 0 {
		fwpmEngineClose0(wfpSession)
		wfpSession = 0
	}
}
