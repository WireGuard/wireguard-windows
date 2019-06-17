/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
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
	routeChangeCallback4    *winipcfg.RouteChangeCallback
	routeChangeCallback6    *winipcfg.RouteChangeCallback
	interfaceChangeCallback *winipcfg.InterfaceChangeCallback
	storedEvents            []interfaceWatcherEvent
}

func (iw *interfaceWatcher) setup(family winipcfg.AddressFamily) {
	var routeChangeCallback **winipcfg.RouteChangeCallback
	var ipversion string
	if family == windows.AF_INET {
		routeChangeCallback = &iw.routeChangeCallback4
		ipversion = "v4"
	} else if family == windows.AF_INET6 {
		routeChangeCallback = &iw.routeChangeCallback6
		ipversion = "v6"
	} else {
		return
	}
	if *routeChangeCallback != nil {
		(*routeChangeCallback).Unregister()
		*routeChangeCallback = nil
	}
	var err error

	log.Printf("Monitoring default %s routes", ipversion)
	*routeChangeCallback, err = monitorDefaultRoutes(family, iw.device, iw.conf.Interface.MTU == 0, iw.tun)
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
	defer iw.setupMutex.Unlock()

	if iw.tun == nil {
		return
	}

	if iw.routeChangeCallback4 != nil {
		iw.routeChangeCallback4.Unregister()
		iw.routeChangeCallback4 = nil
	}
	if iw.routeChangeCallback6 != nil {
		iw.routeChangeCallback6.Unregister()
		iw.routeChangeCallback6 = nil
	}
	if iw.interfaceChangeCallback != nil {
		iw.interfaceChangeCallback.Unregister()
		iw.interfaceChangeCallback = nil
	}

	firewall.DisableFirewall()

	// It seems that the Windows networking stack doesn't like it when we destroy interfaces that have active
	// routes, so to be certain, just remove everything before destroying.
	luid := winipcfg.LUID(iw.tun.LUID())
	luid.FlushRoutes(windows.AF_INET)
	luid.FlushIPAddresses(windows.AF_INET)
	luid.FlushRoutes(windows.AF_INET6)
	luid.FlushIPAddresses(windows.AF_INET6)
	luid.FlushDNS()
}
