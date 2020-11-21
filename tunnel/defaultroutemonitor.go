/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"log"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func bindSocketRoute(family winipcfg.AddressFamily, device *device.Device, ourLUID winipcfg.LUID, lastLUID *winipcfg.LUID, lastIndex *uint32, blackholeWhenLoop bool) error {
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
			continue
		}

		iface, err := r[i].InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}

		if r[i].Metric+iface.Metric < lowestMetric {
			lowestMetric = r[i].Metric + iface.Metric
			index = r[i].InterfaceIndex
			luid = r[i].InterfaceLUID
		}
	}
	if luid == *lastLUID && index == *lastIndex {
		return nil
	}
	*lastLUID = luid
	*lastIndex = index
	blackhole := blackholeWhenLoop && index == 0
	bind, _ := device.Bind().(conn.BindSocketToInterface)
	if bind == nil {
		return nil
	}
	if family == windows.AF_INET {
		log.Printf("Binding v4 socket to interface %d (blackhole=%v)", index, blackhole)
		return bind.BindSocketToInterface4(index, blackhole)
	} else if family == windows.AF_INET6 {
		log.Printf("Binding v6 socket to interface %d (blackhole=%v)", index, blackhole)
		return bind.BindSocketToInterface6(index, blackhole)
	}
	return nil
}

func monitorDefaultRoutes(family winipcfg.AddressFamily, device *device.Device, autoMTU bool, blackholeWhenLoop bool, tun *tun.NativeTun) ([]winipcfg.ChangeCallback, error) {
	var minMTU uint32
	if family == windows.AF_INET {
		minMTU = 576
	} else if family == windows.AF_INET6 {
		minMTU = 1280
	}
	ourLUID := winipcfg.LUID(tun.LUID())
	lastLUID := winipcfg.LUID(0)
	lastIndex := ^uint32(0)
	lastMTU := uint32(0)
	doIt := func() error {
		err := bindSocketRoute(family, device, ourLUID, &lastLUID, &lastIndex, blackholeWhenLoop)
		if err != nil {
			return err
		}
		if !autoMTU {
			return nil
		}
		mtu := uint32(0)
		if lastLUID != 0 {
			iface, err := lastLUID.Interface()
			if err != nil {
				return err
			}
			if iface.MTU > 0 {
				mtu = iface.MTU
			}
		}
		if mtu > 0 && lastMTU != mtu {
			iface, err := ourLUID.IPInterface(family)
			if err != nil {
				return err
			}
			iface.NLMTU = mtu - 80
			if iface.NLMTU < minMTU {
				iface.NLMTU = minMTU
			}
			err = iface.Set()
			if err != nil {
				return err
			}
			tun.ForceMTU(int(iface.NLMTU)) // TODO: having one MTU for both v4 and v6 kind of breaks the windows model, so right now this just gets the second one which is... bad.
			lastMTU = mtu
		}
		return nil
	}
	err := doIt()
	if err != nil {
		return nil, err
	}

	firstBurst := time.Time{}
	burstMutex := sync.Mutex{}
	burstTimer := time.AfterFunc(time.Hour*200, func() {
		burstMutex.Lock()
		firstBurst = time.Time{}
		doIt()
		burstMutex.Unlock()
	})
	burstTimer.Stop()
	bump := func() {
		burstMutex.Lock()
		burstTimer.Reset(time.Millisecond * 150)
		if firstBurst.IsZero() {
			firstBurst = time.Now()
		} else if time.Since(firstBurst) > time.Second*2 {
			firstBurst = time.Time{}
			burstTimer.Stop()
			doIt()
		}
		burstMutex.Unlock()
	}

	cbr, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		if route != nil && route.DestinationPrefix.PrefixLength == 0 {
			bump()
		}
	})
	if err != nil {
		return nil, err
	}
	cbi, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		if notificationType == winipcfg.MibParameterNotification {
			bump()
		}
	})
	if err != nil {
		cbr.Unregister()
		return nil, err
	}
	return []winipcfg.ChangeCallback{cbr, cbi}, nil
}
