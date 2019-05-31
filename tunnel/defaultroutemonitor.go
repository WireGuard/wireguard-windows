/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"log"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func bindSocketRoute(family winipcfg.AddressFamily, device *device.Device, ourLUID winipcfg.LUID, lastLUID *winipcfg.LUID, lastIndex *uint32) error {
	r, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return err
	}
	lowestMetric := ^uint32(0)
	index := uint32(0)       // Zero is "unspecified", which for IP_UNICAST_IF resets the value, which is what we want.
	luid := winipcfg.LUID(0) // Hopefully luid zero is unspecified, but hard to find docs saying so.
	for i := range r {
		if r[i].DestinationPrefix.PrefixLength != 0 || r[i].InterfaceLUID == ourLUID {
			continue
		}
		ifrow, err := r[i].InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			log.Printf("Found default route for interface %d, but not up, so skipping", r[i].InterfaceIndex)
			continue
		}
		if r[i].Metric < lowestMetric {
			lowestMetric = r[i].Metric
			index = r[i].InterfaceIndex
			luid = r[i].InterfaceLUID
		}
	}
	if luid == *lastLUID && index == *lastIndex {
		return nil
	}
	*lastLUID = luid
	*lastIndex = index
	if family == windows.AF_INET {
		log.Printf("Binding UDPv4 socket to interface %d", index)
		return device.BindSocketToInterface4(index)
	} else if family == windows.AF_INET6 {
		log.Printf("Binding UDPv6 socket to interface %d", index)
		return device.BindSocketToInterface6(index)
	}
	return nil
}

func monitorDefaultRoutes(device *device.Device, autoMTU bool, tun *tun.NativeTun) (*winipcfg.RouteChangeCallback, error) {
	ourLUID := winipcfg.LUID(tun.LUID())
	lastLUID4 := winipcfg.LUID(0)
	lastLUID6 := winipcfg.LUID(0)
	lastIndex4 := uint32(0)
	lastIndex6 := uint32(0)
	lastMTU := uint32(0)
	doIt := func() error {
		err := bindSocketRoute(windows.AF_INET, device, ourLUID, &lastLUID4, &lastIndex4)
		if err != nil {
			return err
		}
		err = bindSocketRoute(windows.AF_INET6, device, ourLUID, &lastLUID6, &lastIndex6)
		if err != nil {
			return err
		}
		if !autoMTU {
			return nil
		}
		mtu := uint32(0)
		if lastLUID4 != 0 {
			iface, err := lastLUID4.Interface()
			if err != nil {
				return err
			}
			if iface.MTU > 0 {
				mtu = iface.MTU
			}
		}
		if lastLUID6 != 0 {
			iface, err := lastLUID6.Interface()
			if err != nil {
				return err
			}
			if iface.MTU > 0 && iface.MTU < mtu {
				mtu = iface.MTU
			}
		}
		if mtu > 0 && lastMTU != mtu {
			iface, err := ourLUID.IPInterface(windows.AF_INET)
			if err != nil {
				return err
			}
			iface.NLMTU = mtu - 80
			if iface.NLMTU < 576 {
				iface.NLMTU = 576
			}
			err = iface.Set()
			if err != nil {
				return err
			}
			tun.ForceMTU(int(iface.NLMTU)) //TODO: it sort of breaks the model with v6 mtu and v4 mtu being different. Just set v4 one for now.
			iface, err = ourLUID.IPInterface(windows.AF_INET6)
			if err == nil { // People seem to like to disable IPv6, so we make this non-fatal.
				iface.NLMTU = mtu - 80
				if iface.NLMTU < 1280 {
					iface.NLMTU = 1280
				}
				err = iface.Set()
				if err != nil {
					return err
				}
			}
			lastMTU = mtu
		}
		return nil
	}
	err := doIt()
	if err != nil {
		return nil, err
	}
	cb, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		if route != nil && route.DestinationPrefix.PrefixLength == 0 {
			_ = doIt()
		}
	})
	if err != nil {
		return nil, err
	}
	return cb, nil
}
