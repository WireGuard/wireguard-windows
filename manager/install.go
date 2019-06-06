/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"errors"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel"
)

var cachedServiceManager *mgr.Mgr

func serviceManager() (*mgr.Mgr, error) {
	if cachedServiceManager != nil {
		return cachedServiceManager, nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	cachedServiceManager = m
	return cachedServiceManager, nil
}

func InstallManager() error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	path, err := os.Executable()
	if err != nil {
		return nil
	}

	// TODO: Do we want to bail if executable isn't being run from the right location?

	serviceName := "WireGuardManager"
	service, err := m.OpenService(serviceName)
	if err == nil {
		status, err := service.Query()
		if err != nil {
			service.Close()
			return err
		}
		if status.State != svc.Stopped {
			service.Close()
			return errors.New("Manager already installed and running")
		}
		err = service.Delete()
		service.Close()
		if err != nil {
			return err
		}
		for {
			service, err = m.OpenService(serviceName)
			if err != nil {
				break
			}
			service.Close()
			time.Sleep(time.Second / 3)
		}
	}

	config := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "WireGuard Manager",
	}

	service, err = m.CreateService(serviceName, path, config, "/managerservice")
	if err != nil {
		return err
	}
	service.Start()
	return service.Close()
}

func UninstallManager() error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	serviceName := "WireGuardManager"
	service, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	service.Control(svc.Stop)
	err = service.Delete()
	err2 := service.Close()
	if err != nil {
		return err
	}
	return err2
}

func RunManager() error {
	return svc.Run("WireGuardManager", &managerService{})
}

func InstallTunnel(configPath string) error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	path, err := os.Executable()
	if err != nil {
		return nil
	}

	name, err := conf.NameFromPath(configPath)
	if err != nil {
		return err
	}

	serviceName, err := ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	service, err := m.OpenService(serviceName)
	if err == nil {
		status, err := service.Query()
		if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			service.Close()
			return err
		}
		if status.State != svc.Stopped && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			service.Close()
			return errors.New("Tunnel already installed and running")
		}
		err = service.Delete()
		service.Close()
		if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			return err
		}
		for {
			service, err = m.OpenService(serviceName)
			if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
				break
			}
			service.Close()
			time.Sleep(time.Second / 3)
		}
	}

	config := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "WireGuard Tunnel: " + name,
	}

	service, err = m.CreateService(serviceName, path, config, "/tunnelservice", configPath)
	if err != nil {
		return err
	}
	sidType := uint32(windows.SERVICE_SID_TYPE_UNRESTRICTED)
	err = windows.ChangeServiceConfig2(service.Handle, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&sidType)))
	if err != nil {
		service.Delete()
		service.Close()
		return err
	}

	err = service.Start()
	go trackTunnelService(name, service) // Pass off reference to handle.
	return err
}

func UninstallTunnel(name string) error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	serviceName, err := ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	service, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	service.Control(svc.Stop)
	err = service.Delete()
	err2 := service.Close()
	if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
		return err
	}
	return err2
}

func RunTunnel(confPath string) error {
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		return err
	}
	serviceName, err := ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	return svc.Run(serviceName, &tunnel.Service{confPath})
}
