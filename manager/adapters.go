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
	"golang.zx2c4.com/wireguard/windows/services"
)

func cleanStaleAdapters() {
	defer printPanic()

	m, err := mgr.Connect()
	if err != nil {
		log.Printf("Error connecting to Service Control Manager: %v", err)
		return
	}
	defer m.Disconnect()

	wintun.DeleteMatchingInterfaces(func(wintun *wintun.Wintun) bool {
		interfaceName, err := wintun.InterfaceName()
		if err != nil {
			log.Printf("Removing Wintun interface %s because determining interface name failed: %v", wintun.GUID().String(), err)
			return true
		}
		serviceName, err := services.ServiceNameOfTunnel(interfaceName)
		if err != nil {
			log.Printf("Removing Wintun interface %s because determining tunnel service name failed: %v", interfaceName, err)
			return true
		}
		service, err := m.OpenService(serviceName)
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			log.Printf("Removing orphaned Wintun interface %s", interfaceName)
			return true
		}
		if err != nil {
			log.Printf("Error opening service %s: %v", serviceName, err)
			return false
		}
		defer service.Close()
		config, err := service.Config()
		if err != nil {
			log.Printf("Error getting service %s configuration: %v", serviceName, err)
			return false
		}
		if config.StartType == mgr.StartAutomatic {
			return false
		}
		status, err := service.Query()
		if err != nil {
			log.Printf("Error getting service %s status: %v", serviceName, err)
			return false
		}
		if status.State == svc.Stopped {
			log.Printf("Removing unused Wintun interface %s", interfaceName)
			return true
		}
		return false
	})
}
