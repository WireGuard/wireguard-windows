/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"log"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/tun/wintun"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/services"
)

func cleanupStaleWintunInterfaces() {
	defer printPanic()

	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()

	tun.WintunPool.DeleteMatchingInterfaces(func(wintun *wintun.Interface) bool {
		interfaceName, err := wintun.Name()
		if err != nil {
			log.Printf("Removing Wintun interface %s because determining interface name failed: %v", wintun.GUID().String(), err)
			return true
		}
		serviceName, err := services.ServiceNameOfTunnel(interfaceName)
		if err != nil {
			log.Printf("Removing Wintun interface ‘%s’ because determining tunnel service name failed: %v", interfaceName, err)
			return true
		}
		service, err := m.OpenService(serviceName)
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			log.Printf("Removing Wintun interface ‘%s’ because no service for it exists", interfaceName)
			return true
		} else if err != nil {
			return false
		}
		defer service.Close()
		status, err := service.Query()
		if err != nil {
			return false
		}
		if status.State == svc.Stopped {
			log.Printf("Removing Wintun interface ‘%s’ because its service is stopped", interfaceName)
			return true
		}
		return false
	})
}
