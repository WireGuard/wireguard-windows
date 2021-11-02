/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.zx2c4.com/go118/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func (conf *Config) ToWgQuick() string {
	var output strings.Builder
	output.WriteString("[Interface]\n")

	output.WriteString(fmt.Sprintf("PrivateKey = %s\n", conf.Interface.PrivateKey.String()))

	if conf.Interface.ListenPort > 0 {
		output.WriteString(fmt.Sprintf("ListenPort = %d\n", conf.Interface.ListenPort))
	}

	if len(conf.Interface.Addresses) > 0 {
		addrStrings := make([]string, len(conf.Interface.Addresses))
		for i, address := range conf.Interface.Addresses {
			addrStrings[i] = address.String()
		}
		output.WriteString(fmt.Sprintf("Address = %s\n", strings.Join(addrStrings[:], ", ")))
	}

	if len(conf.Interface.DNS)+len(conf.Interface.DNSSearch) > 0 {
		addrStrings := make([]string, 0, len(conf.Interface.DNS)+len(conf.Interface.DNSSearch))
		for _, address := range conf.Interface.DNS {
			addrStrings = append(addrStrings, address.String())
		}
		addrStrings = append(addrStrings, conf.Interface.DNSSearch...)
		output.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(addrStrings[:], ", ")))
	}

	if conf.Interface.MTU > 0 {
		output.WriteString(fmt.Sprintf("MTU = %d\n", conf.Interface.MTU))
	}

	if len(conf.Interface.PreUp) > 0 {
		output.WriteString(fmt.Sprintf("PreUp = %s\n", conf.Interface.PreUp))
	}
	if len(conf.Interface.PostUp) > 0 {
		output.WriteString(fmt.Sprintf("PostUp = %s\n", conf.Interface.PostUp))
	}
	if len(conf.Interface.PreDown) > 0 {
		output.WriteString(fmt.Sprintf("PreDown = %s\n", conf.Interface.PreDown))
	}
	if len(conf.Interface.PostDown) > 0 {
		output.WriteString(fmt.Sprintf("PostDown = %s\n", conf.Interface.PostDown))
	}
	if conf.Interface.TableOff {
		output.WriteString("Table = off\n")
	}

	for _, peer := range conf.Peers {
		output.WriteString("\n[Peer]\n")

		output.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey.String()))

		if !peer.PresharedKey.IsZero() {
			output.WriteString(fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey.String()))
		}

		if len(peer.AllowedIPs) > 0 {
			addrStrings := make([]string, len(peer.AllowedIPs))
			for i, address := range peer.AllowedIPs {
				addrStrings[i] = address.String()
			}
			output.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(addrStrings[:], ", ")))
		}

		if !peer.Endpoint.IsEmpty() {
			output.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint.String()))
		}

		if peer.PersistentKeepalive > 0 {
			output.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.PersistentKeepalive))
		}
	}
	return output.String()
}

func (config *Config) ToDriverConfiguration() (*driver.Interface, uint32) {
	preallocation := unsafe.Sizeof(driver.Interface{}) + uintptr(len(config.Peers))*unsafe.Sizeof(driver.Peer{})
	for i := range config.Peers {
		preallocation += uintptr(len(config.Peers[i].AllowedIPs)) * unsafe.Sizeof(driver.AllowedIP{})
	}
	var c driver.ConfigBuilder
	c.Preallocate(uint32(preallocation))
	c.AppendInterface(&driver.Interface{
		Flags:      driver.InterfaceHasPrivateKey | driver.InterfaceHasListenPort,
		ListenPort: config.Interface.ListenPort,
		PrivateKey: config.Interface.PrivateKey,
		PeerCount:  uint32(len(config.Peers)),
	})
	for i := range config.Peers {
		flags := driver.PeerHasPublicKey | driver.PeerHasPersistentKeepalive
		if !config.Peers[i].PresharedKey.IsZero() {
			flags |= driver.PeerHasPresharedKey
		}
		var endpoint winipcfg.RawSockaddrInet
		if !config.Peers[i].Endpoint.IsEmpty() {
			addr, err := netip.ParseAddr(config.Peers[i].Endpoint.Host)
			if err == nil {
				flags |= driver.PeerHasEndpoint
				endpoint.SetAddrPort(netip.AddrPortFrom(addr, config.Peers[i].Endpoint.Port))
			}
		}
		c.AppendPeer(&driver.Peer{
			Flags:               flags,
			PublicKey:           config.Peers[i].PublicKey,
			PresharedKey:        config.Peers[i].PresharedKey,
			PersistentKeepalive: config.Peers[i].PersistentKeepalive,
			Endpoint:            endpoint,
			AllowedIPsCount:     uint32(len(config.Peers[i].AllowedIPs)),
		})
		for j := range config.Peers[i].AllowedIPs {
			a := &driver.AllowedIP{Cidr: uint8(config.Peers[i].AllowedIPs[j].Bits())}
			copy(a.Address[:], config.Peers[i].AllowedIPs[j].Addr().AsSlice())
			if config.Peers[i].AllowedIPs[j].Addr().Is4() {
				a.AddressFamily = windows.AF_INET
			} else if config.Peers[i].AllowedIPs[j].Addr().Is6() {
				a.AddressFamily = windows.AF_INET6
			}
			c.AppendAllowedIP(a)
		}
	}
	return c.Interface()
}
