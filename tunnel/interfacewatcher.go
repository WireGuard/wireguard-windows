/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"log"
	"sync"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type interfaceWatcherError struct {
	serviceError services.Error
	err          error
}
type interfaceWatcherEvent struct {
	luid   winipcfg.LUID
	family winipcfg.AddressFamily
}
type interfaceWatcher struct {
	errors chan interfaceWatcherError

	device *device.Device
	conf   *conf.Config
	tun    *tun.NativeTun

	setupMutex              sync.Mutex
	interfaceChangeCallback winipcfg.ChangeCallback
	changeCallbacks4        []winipcfg.ChangeCallback
	changeCallbacks6        []winipcfg.ChangeCallback
	storedEvents            []interfaceWatcherEvent
}

func hasDefaultRoute(family winipcfg.AddressFamily, peers []conf.Peer) bool {
	var (
		foundV401    bool
		foundV41281  bool
		foundV600001 bool
		foundV680001 bool
		foundV400    bool
		foundV600    bool
		v40          = [4]byte{}
		v60          = [16]byte{}
		v48          = [4]byte{0x80}
		v68          = [16]byte{0x80}
	)
	for _, peer := range peers {
		for _, allowedip := range peer.AllowedIPs {
			if allowedip.Cidr == 1 && len(allowedip.IP) == 16 && allowedip.IP.Equal(v60[:]) {
				foundV600001 = true
			} else if allowedip.Cidr == 1 && len(allowedip.IP) == 16 && allowedip.IP.Equal(v68[:]) {
				foundV680001 = true
			} else if allowedip.Cidr == 1 && len(allowedip.IP) == 4 && allowedip.IP.Equal(v40[:]) {
				foundV401 = true
			} else if allowedip.Cidr == 1 && len(allowedip.IP) == 4 && allowedip.IP.Equal(v48[:]) {
				foundV41281 = true
			} else if allowedip.Cidr == 0 && len(allowedip.IP) == 16 && allowedip.IP.Equal(v60[:]) {
				foundV600 = true
			} else if allowedip.Cidr == 0 && len(allowedip.IP) == 4 && allowedip.IP.Equal(v40[:]) {
				foundV400 = true
			}
		}
	}
	if family == windows.AF_INET {
		return foundV400 || (foundV401 && foundV41281)
	} else if family == windows.AF_INET6 {
		return foundV600 || (foundV600001 && foundV680001)
	}
	return false
}

func (iw *interfaceWatcher) setup(family winipcfg.AddressFamily) {
	var changeCallbacks *[]winipcfg.ChangeCallback
	var ipversion string
	if family == windows.AF_INET {
		changeCallbacks = &iw.changeCallbacks4
		ipversion = "v4"
	} else if family == windows.AF_INET6 {
		changeCallbacks = &iw.changeCallbacks6
		ipversion = "v6"
	} else {
		return
	}
	if len(*changeCallbacks) != 0 {
		for _, cb := range *changeCallbacks {
			cb.Unregister()
		}
		*changeCallbacks = nil
	}
	var err error

	log.Printf("Monitoring default %s routes", ipversion)
	*changeCallbacks, err = monitorDefaultRoutes(family, iw.device, iw.conf.Interface.MTU == 0, hasDefaultRoute(family, iw.conf.Peers), iw.tun)
	if err != nil {
		iw.errors <- interfaceWatcherError{services.ErrorBindSocketsToDefaultRoutes, err}
		return
	}

	log.Printf("Setting device %s addresses", ipversion)
	err = configureInterface(family, iw.conf, iw.tun)
	if err != nil {
		iw.errors <- interfaceWatcherError{services.ErrorSetNetConfig, err}
		return
	}
}

func watchInterface() (*interfaceWatcher, error) {
	iw := &interfaceWatcher{
		errors: make(chan interfaceWatcherError, 2),
	}
	var err error
	iw.interfaceChangeCallback, err = winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		iw.setupMutex.Lock()
		defer iw.setupMutex.Unlock()

		if notificationType != winipcfg.MibAddInstance {
			return
		}
		if iw.tun == nil {
			iw.storedEvents = append(iw.storedEvents, interfaceWatcherEvent{iface.InterfaceLUID, iface.Family})
			return
		}
		if iface.InterfaceLUID != winipcfg.LUID(iw.tun.LUID()) {
			return
		}
		iw.setup(iface.Family)
	})
	if err != nil {
		return nil, err
	}
	return iw, nil
}

func (iw *interfaceWatcher) Configure(device *device.Device, conf *conf.Config, tun *tun.NativeTun) {
	iw.setupMutex.Lock()
	defer iw.setupMutex.Unlock()

	iw.device, iw.conf, iw.tun = device, conf, tun
	for _, event := range iw.storedEvents {
		if event.luid == winipcfg.LUID(iw.tun.LUID()) {
			iw.setup(event.family)
		}
	}
	iw.storedEvents = nil
}

func (iw *interfaceWatcher) Destroy() {
	iw.setupMutex.Lock()
	changeCallbacks4 := iw.changeCallbacks4
	changeCallbacks6 := iw.changeCallbacks6
	interfaceChangeCallback := iw.interfaceChangeCallback
	tun := iw.tun
	iw.setupMutex.Unlock()

	if interfaceChangeCallback != nil {
		interfaceChangeCallback.Unregister()
	}
	for _, cb := range changeCallbacks4 {
		cb.Unregister()
	}
	for _, cb := range changeCallbacks6 {
		cb.Unregister()
	}

	iw.setupMutex.Lock()
	if interfaceChangeCallback == iw.interfaceChangeCallback {
		iw.interfaceChangeCallback = nil
	}
	for len(changeCallbacks4) > 0 && len(iw.changeCallbacks4) > 0 {
		iw.changeCallbacks4 = iw.changeCallbacks4[1:]
		changeCallbacks4 = changeCallbacks4[1:]
	}
	for len(changeCallbacks6) > 0 && len(iw.changeCallbacks6) > 0 {
		iw.changeCallbacks6 = iw.changeCallbacks6[1:]
		changeCallbacks6 = changeCallbacks6[1:]
	}
	firewall.DisableFirewall()
	if tun != nil && iw.tun == tun {
		// It seems that the Windows networking stack doesn't like it when we destroy interfaces that have active
		// routes, so to be certain, just remove everything before destroying.
		luid := winipcfg.LUID(tun.LUID())
		luid.FlushRoutes(windows.AF_INET)
		luid.FlushIPAddresses(windows.AF_INET)
		luid.FlushDNS(windows.AF_INET)
		luid.FlushRoutes(windows.AF_INET6)
		luid.FlushIPAddresses(windows.AF_INET6)
		luid.FlushDNS(windows.AF_INET6)
	}
	iw.setupMutex.Unlock()
}
