/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SocketAddressToIP function returns IPv4 or IPv6 address from windows.SocketAddress.
// If the address is neither IPv4 not IPv6 nil is returned.
//TODO: Remove once https://go-review.googlesource.com/c/sys/+/178577 is merged.
func SocketAddressToIP(addr *windows.SocketAddress) net.IP {
	if uintptr(addr.SockaddrLength) >= unsafe.Sizeof(windows.RawSockaddrInet4{}) && addr.Sockaddr.Addr.Family == windows.AF_INET {
		return (*windows.RawSockaddrInet4)(unsafe.Pointer(addr.Sockaddr)).Addr[:]
	} else if uintptr(addr.SockaddrLength) >= unsafe.Sizeof(windows.RawSockaddrInet6{}) && addr.Sockaddr.Addr.Family == windows.AF_INET6 {
		return (*windows.RawSockaddrInet6)(unsafe.Pointer(addr.Sockaddr)).Addr[:]
	} else {
		return nil
	}
}
