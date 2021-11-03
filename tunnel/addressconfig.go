/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"fmt"
	"log"
	"time"

	"golang.zx2c4.com/go118/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []netip.Prefix) {
	if len(addresses) == 0 {
		return
	}
	addrHash := make(map[netip.Addr]bool, len(addresses))
	for i := range addresses {
		addrHash[addresses[i].Addr()] = true
	}
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range interfaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for address := iface.FirstUnicastAddress; address != nil; address = address.Next {
			if ip := netip.AddrFromSlice(address.Address.IP()); addrHash[ip] {
				prefix := netip.PrefixFrom(ip, int(address.OnLinkPrefixLength))
				log.Printf("Cleaning up stale address %s from interface ‘%s’", prefix.String(), iface.FriendlyName())
				iface.LUID.DeleteIPAddress(prefix)
			}
		}
	}
}

func configureInterface(family winipcfg.AddressFamily, conf *conf.Config, luid winipcfg.LUID) error {
	retryOnFailure := services.StartedAtBoot()
	tryTimes := 0
startOver:
	var err error
	if tryTimes > 0 {
		log.Printf("Retrying interface configuration after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
		time.Sleep(time.Second)
		retryOnFailure = retryOnFailure && tryTimes < 15
	}
	tryTimes++

	estimatedRouteCount := 0
	for _, peer := range conf.Peers {
		estimatedRouteCount += len(peer.AllowedIPs)
	}
	routes := make(map[winipcfg.RouteData]bool, estimatedRouteCount)

	foundDefault4 := false
	foundDefault6 := false
	for _, peer := range conf.Peers {
		for _, allowedip := range peer.AllowedIPs {
			route := winipcfg.RouteData{
				Destination: allowedip.Masked(),
				Metric:      0,
			}
			if allowedip.Addr().Is4() {
				if allowedip.Bits() == 0 {
					foundDefault4 = true
				}
				route.NextHop = netip.IPv4Unspecified()
			} else if allowedip.Addr().Is6() {
				if allowedip.Bits() == 0 {
					foundDefault6 = true
				}
				route.NextHop = netip.IPv6Unspecified()
			}
			routes[route] = true
		}
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	for route := range routes {
		r := route
		deduplicatedRoutes = append(deduplicatedRoutes, &r)
	}

	if !conf.Interface.TableOff {
		err = luid.SetRoutesForFamily(family, deduplicatedRoutes)
		if err == windows.ERROR_NOT_FOUND && retryOnFailure {
			goto startOver
		} else if err != nil {
			return fmt.Errorf("unable to set routes: %w", err)
		}
	}

	err = luid.SetIPAddressesForFamily(family, conf.Interface.Addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(family, conf.Interface.Addresses)
		err = luid.SetIPAddressesForFamily(family, conf.Interface.Addresses)
	}
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set ips: %w", err)
	}

	var ipif *winipcfg.MibIPInterfaceRow
	ipif, err = luid.IPInterface(family)
	if err != nil {
		return err
	}
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif.DadTransmits = 0
	ipif.ManagedAddressConfigurationSupported = false
	ipif.OtherStatefulConfigurationSupported = false
	if conf.Interface.MTU > 0 {
		ipif.NLMTU = uint32(conf.Interface.MTU)
	}
	if (family == windows.AF_INET && foundDefault4) || (family == windows.AF_INET6 && foundDefault6) {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	err = ipif.Set()
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set metric and MTU: %w", err)
	}

	err = luid.SetDNS(family, conf.Interface.DNS, conf.Interface.DNSSearch)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set DNS: %w", err)
	}
	return nil
}

func enableFirewall(conf *conf.Config, luid winipcfg.LUID) error {
	doNotRestrict := true
	if len(conf.Peers) == 1 && !conf.Interface.TableOff {
		for _, allowedip := range conf.Peers[0].AllowedIPs {
			if allowedip.Bits() == 0 && allowedip == allowedip.Masked() {
				doNotRestrict = false
				break
			}
		}
	}
	log.Println("Enabling firewall rules")
	return firewall.EnableFirewall(uint64(luid), doNotRestrict, conf.Interface.DNS)
}
