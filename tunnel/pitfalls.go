/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"log"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func evaluateStaticPitfalls() {
	go func() {
		pitfallDnsCacheDisabled()
		pitfallVirtioNetworkDriver()
	}()
}

func evaluateDynamicPitfalls(family winipcfg.AddressFamily, conf *conf.Config, luid winipcfg.LUID) {
	go func() {
		pitfallWeakHostSend(family, conf, luid)
	}()
}

func pitfallDnsCacheDisabled() {
	scm, err := mgr.Connect()
	if err != nil {
		return
	}
	defer scm.Disconnect()
	svc := mgr.Service{Name: "dnscache"}
	svc.Handle, err = windows.OpenService(scm.Handle, windows.StringToUTF16Ptr(svc.Name), windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return
	}
	defer svc.Close()
	cfg, err := svc.Config()
	if err != nil {
		return
	}
	if cfg.StartType != mgr.StartDisabled {
		return
	}

	log.Printf("Warning: the %q (dnscache) service is disabled; please re-enable it", cfg.DisplayName)
}

func pitfallVirtioNetworkDriver() {
	var modules []windows.RTL_PROCESS_MODULE_INFORMATION
	for bufferSize := uint32(128 * 1024); ; {
		moduleBuffer := make([]byte, bufferSize)
		err := windows.NtQuerySystemInformation(windows.SystemModuleInformation, unsafe.Pointer(&moduleBuffer[0]), bufferSize, &bufferSize)
		switch err {
		case windows.STATUS_INFO_LENGTH_MISMATCH:
			continue
		case nil:
			break
		default:
			return
		}
		mods := (*windows.RTL_PROCESS_MODULES)(unsafe.Pointer(&moduleBuffer[0]))
		modules = unsafe.Slice(&mods.Modules[0], mods.NumberOfModules)
		break
	}
	for i := range modules {
		if !strings.EqualFold(windows.ByteSliceToString(modules[i].FullPathName[modules[i].OffsetToFileName:]), "netkvm.sys") {
			continue
		}
		driverPath := `\\?\GLOBALROOT` + windows.ByteSliceToString(modules[i].FullPathName[:])
		var zero windows.Handle
		infoSize, err := windows.GetFileVersionInfoSize(driverPath, &zero)
		if err != nil {
			return
		}
		versionInfo := make([]byte, infoSize)
		err = windows.GetFileVersionInfo(driverPath, 0, infoSize, unsafe.Pointer(&versionInfo[0]))
		if err != nil {
			return
		}
		var fixedInfo *windows.VS_FIXEDFILEINFO
		fixedInfoLen := uint32(unsafe.Sizeof(*fixedInfo))
		err = windows.VerQueryValue(unsafe.Pointer(&versionInfo[0]), `\`, unsafe.Pointer(&fixedInfo), &fixedInfoLen)
		if err != nil {
			return
		}
		const minimumPlausibleVersion = 40 << 48
		const minimumGoodVersion = (100 << 48) | (85 << 32) | (104 << 16) | (20800 << 0)
		version := (uint64(fixedInfo.FileVersionMS) << 32) | uint64(fixedInfo.FileVersionLS)
		if version >= minimumGoodVersion || version < minimumPlausibleVersion {
			return
		}
		log.Println("Warning: the VirtIO network driver (NetKVM) is out of date and may cause known problems; please update to v100.85.104.20800 or later")
		return
	}
}

func pitfallWeakHostSend(family winipcfg.AddressFamily, conf *conf.Config, ourLUID winipcfg.LUID) {
	routingTable, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return
	}
	type endpointRoute struct {
		addr         netip.Addr
		name         string
		lowestMetric uint32
		highestCIDR  uint8
		weakHostSend bool
		finalIsOurs  bool
	}
	endpoints := make([]endpointRoute, 0, len(conf.Peers))
	for _, peer := range conf.Peers {
		addr, err := netip.ParseAddr(peer.Endpoint.Host)
		if err != nil || (addr.Is4() && family != windows.AF_INET) || (addr.Is6() && family != windows.AF_INET6) {
			continue
		}
		endpoints = append(endpoints, endpointRoute{addr: addr, lowestMetric: ^uint32(0)})
	}
	for i := range routingTable {
		var (
			ifrow    *winipcfg.MibIfRow2
			ifacerow *winipcfg.MibIPInterfaceRow
			metric   uint32
		)
		for j := range endpoints {
			r, e := &routingTable[i], &endpoints[j]
			if r.DestinationPrefix.PrefixLength < e.highestCIDR {
				continue
			}
			if !r.DestinationPrefix.Prefix().Contains(e.addr) {
				continue
			}
			if ifrow == nil {
				ifrow, err = r.InterfaceLUID.Interface()
				if err != nil {
					continue
				}
			}
			if ifrow.OperStatus != winipcfg.IfOperStatusUp {
				continue
			}
			if ifacerow == nil {
				ifacerow, err = r.InterfaceLUID.IPInterface(family)
				if err != nil {
					continue
				}
				metric = r.Metric + ifacerow.Metric
			}
			if r.DestinationPrefix.PrefixLength == e.highestCIDR && metric > e.lowestMetric {
				continue
			}
			e.lowestMetric = metric
			e.highestCIDR = r.DestinationPrefix.PrefixLength
			e.finalIsOurs = r.InterfaceLUID == ourLUID
			if !e.finalIsOurs {
				e.name = ifrow.Alias()
				e.weakHostSend = ifacerow.ForwardingEnabled || ifacerow.WeakHostSend
			}
		}
	}
	problematicInterfaces := make(map[string]bool, len(endpoints))
	for _, e := range endpoints {
		if e.weakHostSend && e.finalIsOurs {
			problematicInterfaces[e.name] = true
		}
	}
	for iface := range problematicInterfaces {
		log.Printf("Warning: the %q interface has Forwarding/WeakHostSend enabled, which will cause routing loops", iface)
	}
}
