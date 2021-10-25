/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []net.IPNet) {
	if len(addresses) == 0 {
		return
	}
	addrToStr := func(ip *net.IP) string {
		if ip4 := ip.To4(); ip4 != nil {
			return string(ip4)
		}
		return string(*ip)
	}
	addrHash := make(map[string]bool, len(addresses))
	for i := range addresses {
		addrHash[addrToStr(&addresses[i].IP)] = true
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
			ip := address.Address.IP()
			if addrHash[addrToStr(&ip)] {
				ipnet := net.IPNet{IP: ip, Mask: net.CIDRMask(int(address.OnLinkPrefixLength), 8*len(ip))}
				log.Printf("Cleaning up stale address %s from interface ‘%s’", ipnet.String(), iface.FriendlyName())
				iface.LUID.DeleteIPAddress(ipnet)
			}
		}
	}
}

func configureInterface(family winipcfg.AddressFamily, conf *conf.Config, luid winipcfg.LUID) error {
	systemJustBooted := windows.DurationSinceBoot() <= time.Minute*10
	tryTimes := 0
startOver:
	var err error
	if tryTimes > 0 {
		log.Printf("Retrying interface configuration after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
		time.Sleep(time.Second)
		systemJustBooted = systemJustBooted && tryTimes < 15
	}
	tryTimes++

	estimatedRouteCount := 0
	for _, peer := range conf.Peers {
		estimatedRouteCount += len(peer.AllowedIPs)
	}
	routes := make([]winipcfg.RouteData, 0, estimatedRouteCount)
	addresses := make([]net.IPNet, len(conf.Interface.Addresses))
	var haveV4Address, haveV6Address bool
	for i, addr := range conf.Interface.Addresses {
		addresses[i] = addr.IPNet()
		if addr.Bits() == 32 {
			haveV4Address = true
		} else if addr.Bits() == 128 {
			haveV6Address = true
		}
	}

	foundDefault4 := false
	foundDefault6 := false
	for _, peer := range conf.Peers {
		for _, allowedip := range peer.AllowedIPs {
			allowedip.MaskSelf()
			if (allowedip.Bits() == 32 && !haveV4Address) || (allowedip.Bits() == 128 && !haveV6Address) {
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
				route.NextHop = net.IPv4zero
			} else if allowedip.Bits() == 128 {
				if allowedip.Cidr == 0 {
					foundDefault6 = true
				}
				route.NextHop = net.IPv6zero
			}
			routes = append(routes, route)
		}
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Metric != routes[j].Metric {
			return routes[i].Metric < routes[j].Metric
		}
		if c := bytes.Compare(routes[i].NextHop, routes[j].NextHop); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask); c != 0 {
			return c < 0
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
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}

	if !conf.Interface.TableOff {
		err = luid.SetRoutesForFamily(family, deduplicatedRoutes)
		if err == windows.ERROR_NOT_FOUND && systemJustBooted {
			goto startOver
		} else if err != nil {
			return fmt.Errorf("unable to set routes: %w", err)
		}
	}

	err = luid.SetIPAddressesForFamily(family, addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(family, addresses)
		err = luid.SetIPAddressesForFamily(family, addresses)
	}
	if err == windows.ERROR_NOT_FOUND && systemJustBooted {
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
	if err == windows.ERROR_NOT_FOUND && systemJustBooted {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set metric and MTU: %w", err)
	}

	err = luid.SetDNS(family, conf.Interface.DNS, conf.Interface.DNSSearch)
	if err == windows.ERROR_NOT_FOUND && systemJustBooted {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set DNS: %w", err)
	}
	return nil
}

func enableFirewall(conf *conf.Config, luid winipcfg.LUID) error {
	doNotRestrict := true
	if len(conf.Peers) == 1 && !conf.Interface.TableOff {
	nextallowedip:
		for _, allowedip := range conf.Peers[0].AllowedIPs {
			if allowedip.Cidr == 0 {
				for _, b := range allowedip.IP {
					if b != 0 {
						continue nextallowedip
					}
				}
				doNotRestrict = false
				break
			}
		}
	}
	log.Println("Enabling firewall rules")
	return firewall.EnableFirewall(uint64(luid), doNotRestrict, conf.Interface.DNS)
}
