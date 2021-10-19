/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"log"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func checkForPitfalls() {
	go func() {
		pitfallDnsCacheDisabled()
		pitfallVirtioNetworkDriver()
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

/* TODO: put this into x/sys/windows */

var versionDll = windows.NewLazySystemDLL("version.dll")
var getFileVersionInfo = versionDll.NewProc("GetFileVersionInfoW")
var getFileVersionInfoSize = versionDll.NewProc("GetFileVersionInfoSizeW")
var verQueryValue = versionDll.NewProc("VerQueryValueW")

type VS_FIXEDFILEINFO struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

var ntQuerySystemInformation = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQuerySystemInformation")

const systemModuleInformation = 11

type RTL_PROCESS_MODULE_INFORMATION struct {
	Section          windows.Handle
	MappedBase       uintptr
	ImageBase        uintptr
	ImageSize        uint32
	Flags            uint32
	LoadOrderIndex   uint16
	InitOrderIndex   uint16
	LoadCount        uint16
	OffsetToFileName uint16
	FullPathName     [256]byte
}

type RTL_PROCESS_MODULES struct {
	NumberOfModules uint32
	FirstModule     RTL_PROCESS_MODULE_INFORMATION
}

func pitfallVirtioNetworkDriver() {
	var modules []RTL_PROCESS_MODULE_INFORMATION
	for bufferSize := uint32(128 * 1024); ; {
		moduleBuffer := make([]byte, bufferSize)
		ret, _, _ := ntQuerySystemInformation.Call(systemModuleInformation, uintptr(unsafe.Pointer(&moduleBuffer[0])), uintptr(bufferSize), uintptr(unsafe.Pointer(&bufferSize)))
		switch windows.NTStatus(ret) {
		case windows.STATUS_INFO_LENGTH_MISMATCH:
			continue
		case windows.STATUS_SUCCESS:
			break
		default:
			return
		}
		mods := (*RTL_PROCESS_MODULES)(unsafe.Pointer(&moduleBuffer[0]))
		modules = unsafe.Slice(&mods.FirstModule, mods.NumberOfModules)
		break
	}
	for i := range modules {
		if !strings.EqualFold(windows.ByteSliceToString(modules[i].FullPathName[modules[i].OffsetToFileName:]), "netkvm.sys") {
			continue
		}
		driverPath := `\\?\GLOBALROOT` + windows.ByteSliceToString(modules[i].FullPathName[:])
		zero := uint32(0)
		ret, _, _ := getFileVersionInfoSize.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(driverPath))), uintptr(unsafe.Pointer(&zero)))
		if ret == 0 {
			return
		}
		infoSize := uint32(ret)
		versionInfo := make([]byte, infoSize)
		ret, _, _ = getFileVersionInfo.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(driverPath))), 0, uintptr(infoSize), uintptr(unsafe.Pointer(&versionInfo[0])))
		var fixedInfo *VS_FIXEDFILEINFO
		fixedInfoLen := uint32(unsafe.Sizeof(*fixedInfo))
		ret, _, _ = verQueryValue.Call(uintptr(unsafe.Pointer(&versionInfo[0])), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(`\`))), uintptr(unsafe.Pointer(&fixedInfo)), uintptr(unsafe.Pointer(&fixedInfoLen)))
		if ret == 0 {
			return
		}
		const minimumGoodVersion = (100 << 48) | (85 << 32) | (104 << 16) | (20800 << 0)
		version := (uint64(fixedInfo.FileVersionMS) << 32) | uint64(fixedInfo.FileVersionLS)
		if version >= minimumGoodVersion {
			return
		}
		log.Println("Warning: the VirtIO network driver (NetKVM) is out of date and may cause known problems; please update to v100.85.104.20800 or later")
		return
	}
}
