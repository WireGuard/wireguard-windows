/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
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
	errors  chan interfaceWatcherError
	started chan winipcfg.AddressFamily

	conf    *conf.Config
	adapter *driver.Adapter
	luid    winipcfg.LUID

	setupMutex              sync.Mutex
	interfaceChangeCallback winipcfg.ChangeCallback
	changeCallbacks4        []winipcfg.ChangeCallback
	changeCallbacks6        []winipcfg.ChangeCallback
	storedEvents            []interfaceWatcherEvent
	watchdog                *time.Timer
}

func (iw *interfaceWatcher) setup(family winipcfg.AddressFamily) {
	iw.watchdog.Stop()
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

	if iw.conf.Interface.MTU == 0 {
		log.Printf("Monitoring MTU of default %s routes", ipversion)
		*changeCallbacks, err = monitorMTU(family, iw.luid)
		if err != nil {
			iw.errors <- interfaceWatcherError{services.ErrorMonitorMTUChanges, err}
			return
		}
	}

	log.Printf("Setting device %s addresses", ipversion)
	err = configureInterface(family, iw.conf, iw.luid)
	if err != nil {
		iw.errors <- interfaceWatcherError{services.ErrorSetNetConfig, err}
		return
	}
	evaluateDynamicPitfalls(family, iw.conf, iw.luid)

	iw.started <- family
}

func watchInterface() (*interfaceWatcher, error) {
	iw := &interfaceWatcher{
		errors:  make(chan interfaceWatcherError, 2),
		started: make(chan winipcfg.AddressFamily, 4),
	}
	iw.watchdog = time.AfterFunc(time.Duration(1<<63-1), func() {
		iw.errors <- interfaceWatcherError{services.ErrorCreateNetworkAdapter, errors.New("TCP/IP interface for adapter did not appear after one minute")}
	})
	iw.watchdog.Stop()
	var err error
	iw.interfaceChangeCallback, err = winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		iw.setupMutex.Lock()
		defer iw.setupMutex.Unlock()

		if notificationType != winipcfg.MibAddInstance {
			return
		}
		if iw.luid == 0 {
			iw.storedEvents = append(iw.storedEvents, interfaceWatcherEvent{iface.InterfaceLUID, iface.Family})
			return
		}
		if iface.InterfaceLUID != iw.luid {
			return
		}
		iw.setup(iface.Family)

		if state, err := iw.adapter.AdapterState(); err == nil && state == driver.AdapterStateDown {
			log.Println("Reinitializing adapter configuration")
			err = iw.adapter.SetConfiguration(iw.conf.ToDriverConfiguration())
			if err != nil {
				log.Println(fmt.Errorf("%v: %w", services.ErrorDeviceSetConfig, err))
			}
			err = iw.adapter.SetAdapterState(driver.AdapterStateUp)
			if err != nil {
				log.Println(fmt.Errorf("%v: %w", services.ErrorDeviceBringUp, err))
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("unable to register interface change callback: %w", err)
	}
	return iw, nil
}

func (iw *interfaceWatcher) Configure(adapter *driver.Adapter, conf *conf.Config, luid winipcfg.LUID) {
	iw.setupMutex.Lock()
	defer iw.setupMutex.Unlock()
	iw.watchdog.Reset(time.Minute)

	iw.adapter, iw.conf, iw.luid = adapter, conf, luid
	for _, event := range iw.storedEvents {
		if event.luid == luid {
			iw.setup(event.family)
		}
	}
	iw.storedEvents = nil
}

func (iw *interfaceWatcher) Destroy() {
	iw.setupMutex.Lock()
	iw.watchdog.Stop()
	changeCallbacks4 := iw.changeCallbacks4
	changeCallbacks6 := iw.changeCallbacks6
	interfaceChangeCallback := iw.interfaceChangeCallback
	luid := iw.luid
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
	if luid != 0 && iw.luid == luid {
		// It seems that the Windows networking stack doesn't like it when we destroy interfaces that have active
		// routes, so to be certain, just remove everything before destroying.
		luid.FlushRoutes(windows.AF_INET)
		luid.FlushIPAddresses(windows.AF_INET)
		luid.FlushDNS(windows.AF_INET)
		luid.FlushRoutes(windows.AF_INET6)
		luid.FlushIPAddresses(windows.AF_INET6)
		luid.FlushDNS(windows.AF_INET6)
	}
	iw.setupMutex.Unlock()
}
