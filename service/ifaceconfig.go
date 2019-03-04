/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"bytes"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/winipcfg"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/windows/conf"
	"net"
	"sort"
	"unsafe"
)

const (
	sockoptIP_UNICAST_IF   = 31
	sockoptIPV6_UNICAST_IF = 31
)

func htonl(val uint32) uint32 {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, val)
	return *(*uint32)(unsafe.Pointer(&bytes[0]))
}

func bindSocketRoute(family winipcfg.AddressFamily, device *device.Device, ourLuid uint64, lastLuid *uint64) error {
	routes, err := winipcfg.GetRoutes(family)
	if err != nil {
		return err
	}
	lowestMetric := ^uint32(0)
	index := uint32(0) // Zero is "unspecified", which for IP_UNICAST_IF resets the value, which is what we want.
	luid := uint64(0)  // Hopefully luid zero is unspecified, but hard to find docs saying so.
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 || route.InterfaceLuid == ourLuid {
			continue
		}
		if route.Metric < lowestMetric {
			lowestMetric = route.Metric
			index = route.InterfaceIndex
			luid = route.InterfaceLuid
		}
	}
	if luid == *lastLuid {
		return nil
	}
	*lastLuid = luid
	if family == winipcfg.AF_INET {
		return device.BindSocketToInterface4(index)
	} else if family == winipcfg.AF_INET6 {
		return device.BindSocketToInterface6(index)
	}
	return nil
}

func monitorDefaultRoutes(device *device.Device, guid *windows.GUID) (*winipcfg.RouteChangeCallback, error) {
	ourLuid, err := winipcfg.InterfaceGuidToLuid(guid)
	lastLuid4 := uint64(0)
	lastLuid6 := uint64(0)
	if err != nil {
		return nil, err
	}
	doIt := func() error {
		err = bindSocketRoute(winipcfg.AF_INET, device, ourLuid, &lastLuid4)
		if err != nil {
			return err
		}
		err = bindSocketRoute(winipcfg.AF_INET6, device, ourLuid, &lastLuid6)
		if err != nil {
			return err
		}
		return nil
	}
	err = doIt()
	if err != nil {
		return nil, err
	}
	cb, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.Route) {
		if route.DestinationPrefix.PrefixLength == 0 {
			_ = doIt()
		}
	})
	if err != nil {
		return nil, err
	}
	return cb, nil
}

func configureInterface(conf *conf.Config, guid *windows.GUID) error {
	iface, err := winipcfg.InterfaceFromGUID(guid)
	if err != nil {
		return err
	}

	routeCount := len(conf.Interface.Addresses)
	for _, peer := range conf.Peers {
		routeCount += len(peer.AllowedIPs)
	}
	routes := make([]winipcfg.RouteData, routeCount)
	routeCount = 0
	var firstGateway4 *net.IP
	var firstGateway6 *net.IP
	addresses := make([]*net.IPNet, len(conf.Interface.Addresses))
	for i, addr := range conf.Interface.Addresses {
		ipnet := addr.IPNet()
		addresses[i] = &ipnet
		gateway := ipnet.IP.Mask(ipnet.Mask)
		if addr.Bits() == 32 && firstGateway4 == nil {
			firstGateway4 = &gateway
		} else if addr.Bits() == 128 && firstGateway6 == nil {
			firstGateway6 = &gateway
		}
		routes[routeCount] = winipcfg.RouteData{
			Destination: net.IPNet{
				IP:   gateway,
				Mask: ipnet.Mask,
			},
			NextHop: gateway,
			Metric:  0,
		}
		routeCount++
	}

	foundDefault4 := false
	foundDefault6 := false
	for _, peer := range conf.Peers {
		for _, allowedip := range peer.AllowedIPs {
			if (allowedip.Bits() == 32 && firstGateway4 == nil) || (allowedip.Bits() == 128 && firstGateway6 == nil) {
				return errors.New("Due to a Windows limitation, one cannot have interface routes without an interface address")
			}
			routes[routeCount] = winipcfg.RouteData{
				Destination: allowedip.IPNet(),
				Metric:      0,
			}
			if allowedip.Bits() == 32 {
				if allowedip.Cidr == 0 {
					foundDefault4 = true
				}
				routes[routeCount].NextHop = *firstGateway4
			} else if allowedip.Bits() == 128 {
				if allowedip.Cidr == 0 {
					foundDefault6 = true
				}
				routes[routeCount].NextHop = *firstGateway6
			}
			routeCount++
		}
	}

	err = iface.SetAddresses(addresses)
	if err != nil {
		return err
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, routeCount)
	routeCount = 0
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Metric < routes[j].Metric {
			return true
		}
		if bytes.Compare(routes[i].NextHop, routes[j].NextHop) == -1 {
			return true
		}
		if bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP) == -1 {
			return true
		}
		if bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask) == -1 {
			return true
		}
		return false
	})
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Metric == routes[i-1].Metric &&
			bytes.Equal(routes[i].NextHop, routes[i-1].NextHop) &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes[routeCount] = &routes[i]
		routeCount++
	}

	err = iface.SetRoutes(deduplicatedRoutes)
	if err != nil {
		return nil
	}

	err = iface.SetDNS(conf.Interface.Dns)
	if err != nil {
		return err
	}

	ipif, err := iface.GetIpInterface(winipcfg.AF_INET)
	if err != nil {
		return err
	}
	if foundDefault4 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	err = ipif.Set()
	if err != nil {
		return err
	}

	ipif, err = iface.GetIpInterface(winipcfg.AF_INET6)
	if err != nil {
		return err
	}
	if foundDefault6 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	ipif.DadTransmits = 0
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	err = ipif.Set()
	if err != nil {
		return err
	}

	return nil
}
