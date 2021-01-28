/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//sys	internetGetConnectedState(flags *uint32, reserved uint32) (connected bool) = wininet.InternetGetConnectedState

func resolveHostname(name string) (resolvedIPString string, err error) {
	maxTries := 10
	systemJustBooted := windows.DurationSinceBoot() <= time.Minute*4
	if systemJustBooted {
		maxTries *= 4
	}
	for i := 0; i < maxTries; i++ {
		resolvedIPString, err = resolveHostnameOnce(name)
		if err == nil {
			return
		}
		if err == windows.WSATRY_AGAIN {
			log.Printf("Temporary DNS error when resolving %s, sleeping for 4 seconds", name)
			time.Sleep(time.Second * 4)
			continue
		}
		var state uint32
		if err == windows.WSAHOST_NOT_FOUND && systemJustBooted && !internetGetConnectedState(&state, 0) {
			log.Printf("Host not found when resolving %s, but no Internet connection available, sleeping for 4 seconds", name)
			time.Sleep(time.Second * 4)
			continue
		}
		return
	}
	return
}

func resolveHostnameOnce(name string) (resolvedIPString string, err error) {
	hints := windows.AddrinfoW{
		Family:   windows.AF_UNSPEC,
		Socktype: windows.SOCK_DGRAM,
		Protocol: windows.IPPROTO_IP,
	}
	var result *windows.AddrinfoW
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	err = windows.GetAddrInfoW(name16, nil, &hints, &result)
	if err != nil {
		return
	}
	if result == nil {
		err = windows.WSAHOST_NOT_FOUND
		return
	}
	defer windows.FreeAddrInfoW(result)
	ipv6 := ""
	for ; result != nil; result = result.Next {
		addr := unsafe.Pointer(result.Addr)
		switch result.Family {
		case windows.AF_INET:
			a := (*syscall.RawSockaddrInet4)(addr).Addr
			return net.IP{a[0], a[1], a[2], a[3]}.String(), nil
		case windows.AF_INET6:
			if len(ipv6) != 0 {
				continue
			}
			a := (*syscall.RawSockaddrInet6)(addr).Addr
			ipv6 = net.IP{a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]}.String()
			scope := uint32((*syscall.RawSockaddrInet6)(addr).Scope_id)
			if scope != 0 {
				ipv6 += fmt.Sprintf("%%%d", scope)
			}
		}
	}
	if len(ipv6) != 0 {
		return ipv6, nil
	}
	err = windows.WSAHOST_NOT_FOUND
	return
}
