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
	"golang.zx2c4.com/wireguard/windows/services"
)

//sys	internetGetConnectedState(flags *uint32, reserved uint32) (connected bool) = wininet.InternetGetConnectedState

func resolveHostname(name string) (resolvedIPString string, err error) {
	maxTries := 10
	if services.StartedAtBoot() {
		maxTries *= 4
	}
	for i := 0; i < maxTries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 4)
		}
		resolvedIPString, err = resolveHostnameOnce(name)
		if err == nil {
			return
		}
		if err == windows.WSATRY_AGAIN {
			log.Printf("Temporary DNS error when resolving %s, sleeping for 4 seconds", name)
			continue
		}
		var state uint32
		if err == windows.WSAHOST_NOT_FOUND && services.StartedAtBoot() && !internetGetConnectedState(&state, 0) {
			log.Printf("Host not found when resolving %s, but no Internet connection available, sleeping for 4 seconds", name)
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
		switch result.Family {
		case windows.AF_INET:
			return (net.IP)((*syscall.RawSockaddrInet4)(unsafe.Pointer(result.Addr)).Addr[:]).String(), nil
		case windows.AF_INET6:
			if len(ipv6) != 0 {
				continue
			}
			a := (*syscall.RawSockaddrInet6)(unsafe.Pointer(result.Addr))
			ipv6 = (net.IP)(a.Addr[:]).String()
			if a.Scope_id != 0 {
				ipv6 += fmt.Sprintf("%%%d", a.Scope_id)
			}
		}
	}
	if len(ipv6) != 0 {
		return ipv6, nil
	}
	err = windows.WSAHOST_NOT_FOUND
	return
}

func (config *Config) ResolveEndpoints() error {
	for i := range config.Peers {
		if config.Peers[i].Endpoint.IsEmpty() {
			continue
		}
		var err error
		config.Peers[i].Endpoint.Host, err = resolveHostname(config.Peers[i].Endpoint.Host)
		if err != nil {
			return err
		}
	}
	return nil
}
