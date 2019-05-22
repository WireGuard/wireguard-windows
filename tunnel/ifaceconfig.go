/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"log"
	"net"
	"sort"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/winipcfg"
	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
)

func cleanupAddressesOnDisconnectedInterfaces(addresses []*net.IPNet) {
	if len(addresses) == 0 {
		return
	}
	includedInAddresses := func(a *net.IPNet) bool {
		//TODO: this makes the whole algorithm O(n^2). But we can't stick net.IPNet in a Go hashmap. Bummer!
		for _, addr := range addresses {
			ip := addr.IP
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			mA, _ := addr.Mask.Size()
			mB, _ := a.Mask.Size()
			if bytes.Equal(ip, a.IP) && mA == mB {
				return true
			}
		}
		return false
	}
	interfaces, err := winipcfg.GetInterfaces()
	if err != nil {
		return
	}
	for _, iface := range interfaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		addressesToKeep := make([]*net.IPNet, 0, len(iface.UnicastAddresses))
		for _, address := range iface.UnicastAddresses {
			ip := address.Address.Address
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			ipnet := &net.IPNet{ip, net.CIDRMask(int(address.OnLinkPrefixLength), 8*len(ip))}
			if !includedInAddresses(ipnet) {
				addressesToKeep = append(addressesToKeep, ipnet)
			}
		}
		if len(addressesToKeep) < len(iface.UnicastAddresses) {
			log.Printf("Cleaning up stale addresses from interface '%s'", iface.FriendlyName)
			iface.SetAddresses(addressesToKeep)
		}
	}
}

func configureInterface(conf *conf.Config, tun *tun.NativeTun) error {
	iface, err := winipcfg.InterfaceFromLUID(tun.LUID())
	if err != nil {
		return err
	}

	estimatedRouteCount := len(conf.Interface.Addresses)
	for _, peer := range conf.Peers {
		estimatedRouteCount += len(peer.AllowedIPs)
	}
	routes := make([]winipcfg.RouteData, 0, estimatedRouteCount)
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
		routes = append(routes, winipcfg.RouteData{
			Destination: net.IPNet{
				IP:   gateway,
				Mask: ipnet.Mask,
			},
			NextHop: gateway,
			Metric:  0,
		})
	}

	foundDefault4 := false
	foundDefault6 := false
	for _, peer := range conf.Peers {
		for _, allowedip := range peer.AllowedIPs {
			if (allowedip.Bits() == 32 && firstGateway4 == nil) || (allowedip.Bits() == 128 && firstGateway6 == nil) {
				continue
			}
			route := winipcfg.RouteData{
				Destination: allowedip.IPNet(),
				Metric:      0,
			}
			if allowedip.Bits() == 32 {
				if allowedip.Cidr == 0 {
					foundDefault4 = true
				}
				route.NextHop = *firstGateway4
			} else if allowedip.Bits() == 128 {
				if allowedip.Cidr == 0 {
					foundDefault6 = true
				}
				route.NextHop = *firstGateway6
			}
			routes = append(routes, route)
		}
	}

	err = iface.SetAddresses(addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(addresses)
		err = iface.SetAddresses(addresses)
	}
	if err != nil {
		return err
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Metric < routes[j].Metric ||
			bytes.Compare(routes[i].NextHop, routes[j].NextHop) == -1 ||
			bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP) == -1 ||
			bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask) == -1
	})
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Metric == routes[i-1].Metric &&
			bytes.Equal(routes[i].NextHop, routes[i-1].NextHop) &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}

	err = iface.SetRoutes(deduplicatedRoutes)
	if err != nil {
		return nil
	}

	err = iface.SetDNS(conf.Interface.DNS)
	if err != nil {
		return err
	}

	ipif, err := iface.GetIPInterface(windows.AF_INET)
	if err != nil {
		return err
	}
	if foundDefault4 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	if conf.Interface.MTU > 0 {
		ipif.NLMTU = uint32(conf.Interface.MTU)
		tun.ForceMTU(int(ipif.NLMTU))
	}
	err = ipif.Set()
	if err != nil {
		return err
	}

	ipif, err = iface.GetIPInterface(windows.AF_INET6)
	if err != nil {
		return err
	}
	if foundDefault6 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	if conf.Interface.MTU > 0 {
		ipif.NLMTU = uint32(conf.Interface.MTU)
	}
	ipif.DadTransmits = 0
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	err = ipif.Set()
	if err != nil {
		return err
	}

	return nil
}

func unconfigureInterface(tun *tun.NativeTun) {
	// It seems that the Windows networking stack doesn't like it when we destroy interfaces that have active
	// routes, so to be certain, just remove everything before destroying.
	luid := tun.LUID()
	winipcfg.FlushInterfaceRoutes(luid, windows.AF_INET)
	winipcfg.FlushInterfaceIPAddresses(luid, windows.AF_INET)
	winipcfg.FlushInterfaceRoutes(luid, windows.AF_INET6)
	winipcfg.FlushInterfaceIPAddresses(luid, windows.AF_INET6)

	//TODO: also flush DNS servers once rozmansi fixes the API for that to take a LUID

	firewall.DisableFirewall()
}

func enableFirewall(conf *conf.Config, tun *tun.NativeTun) error {
	restrictAll := false
	if len(conf.Peers) == 1 {
	nextallowedip:
		for _, allowedip := range conf.Peers[0].AllowedIPs {
			if allowedip.Cidr == 0 {
				for _, b := range allowedip.IP {
					if b != 0 {
						continue nextallowedip
					}
				}
				restrictAll = true
				break
			}
		}
	}
	if restrictAll && len(conf.Interface.DNS) == 0 {
		log.Println("Warning: no DNS server specified, despite having an allowed IPs of 0.0.0.0/0 or ::/0. There may be connectivity issues.")
	}
	return firewall.EnableFirewall(tun.LUID(), conf.Interface.DNS, restrictAll)
}
