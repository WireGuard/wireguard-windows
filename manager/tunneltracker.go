/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/services"
)

func trackExistingTunnels() error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	names, err := conf.ListConfigNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		serviceName, err := ServiceNameOfTunnel(name)
		if err != nil {
			continue
		}
		service, err := m.OpenService(serviceName)
		if err != nil {
			continue
		}
		go trackTunnelService(name, service)
	}
	return nil
}

var serviceTrackerCallbackPtr = windows.NewCallback(func(notifier *windows.SERVICE_NOTIFY) uintptr {
	return 0
})

var trackedTunnels = make(map[string]TunnelState)
var trackedTunnelsLock = sync.Mutex{}

func svcStateToTunState(s svc.State) TunnelState {
	switch s {
	case svc.StartPending:
		return TunnelStarting
	case svc.Running:
		return TunnelStarted
	case svc.StopPending:
		return TunnelStopping
	case svc.Stopped:
		return TunnelStopped
	default:
		return TunnelUnknown
	}
}

func trackedTunnelsGlobalState() (state TunnelState) {
	state = TunnelStopped
	trackedTunnelsLock.Lock()
	defer trackedTunnelsLock.Unlock()
	for _, s := range trackedTunnels {
		if s == TunnelStarting {
			return TunnelStarting
		} else if s == TunnelStopping {
			return TunnelStopping
		} else if s == TunnelStarted || s == TunnelUnknown {
			state = TunnelStarted
		}
	}
	return
}

func trackTunnelService(tunnelName string, service *mgr.Service) {
	defer func() {
		service.Close()
		log.Printf("[%s] Tunnel service tracker finished", tunnelName)
	}()

	trackedTunnelsLock.Lock()
	if _, found := trackedTunnels[tunnelName]; found {
		trackedTunnelsLock.Unlock()
		return
	}
	trackedTunnels[tunnelName] = TunnelUnknown
	trackedTunnelsLock.Unlock()
	defer func() {
		trackedTunnelsLock.Lock()
		delete(trackedTunnels, tunnelName)
		trackedTunnelsLock.Unlock()
	}()

	const serviceNotifications = windows.SERVICE_NOTIFY_RUNNING | windows.SERVICE_NOTIFY_START_PENDING | windows.SERVICE_NOTIFY_STOP_PENDING | windows.SERVICE_NOTIFY_STOPPED | windows.SERVICE_NOTIFY_DELETE_PENDING
	notifier := &windows.SERVICE_NOTIFY{
		Version:        windows.SERVICE_NOTIFY_STATUS_CHANGE,
		NotifyCallback: serviceTrackerCallbackPtr,
	}

	checkForDisabled := func() (shouldReturn bool) {
		config, err := service.Config()
		if err == windows.ERROR_SERVICE_MARKED_FOR_DELETE || config.StartType == windows.SERVICE_DISABLED {
			log.Printf("[%s] Found disabled service via timeout, so deleting", tunnelName)
			service.Delete()
			trackedTunnelsLock.Lock()
			trackedTunnels[tunnelName] = TunnelStopped
			trackedTunnelsLock.Unlock()
			IPCServerNotifyTunnelChange(tunnelName, TunnelStopped, nil)
			return true
		}
		return false
	}
	if checkForDisabled() {
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	lastState := TunnelUnknown
	for {
		err := windows.NotifyServiceStatusChange(service.Handle, serviceNotifications, notifier)
		switch err {
		case nil:
			for {
				if windows.SleepEx(uint32(time.Second*3/time.Millisecond), true) == windows.WAIT_IO_COMPLETION {
					break
				} else if checkForDisabled() {
					return
				}
			}
		case windows.ERROR_SERVICE_MARKED_FOR_DELETE:
			trackedTunnelsLock.Lock()
			trackedTunnels[tunnelName] = TunnelStopped
			trackedTunnelsLock.Unlock()
			IPCServerNotifyTunnelChange(tunnelName, TunnelStopped, nil)
			return
		case windows.ERROR_SERVICE_NOTIFY_CLIENT_LAGGING:
			continue
		default:
			trackedTunnelsLock.Lock()
			trackedTunnels[tunnelName] = TunnelStopped
			trackedTunnelsLock.Unlock()
			IPCServerNotifyTunnelChange(tunnelName, TunnelStopped, fmt.Errorf("Unable to continue monitoring service, so stopping: %v", err))
			service.Control(svc.Stop)
			return
		}

		state := svcStateToTunState(svc.State(notifier.ServiceStatus.CurrentState))
		var tunnelError error
		if state == TunnelStopped {
			if notifier.ServiceStatus.Win32ExitCode == uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
				maybeErr := services.Error(notifier.ServiceStatus.ServiceSpecificExitCode)
				if maybeErr != services.ErrorSuccess {
					tunnelError = maybeErr
				}
			} else {
				switch notifier.ServiceStatus.Win32ExitCode {
				case uint32(windows.NO_ERROR), uint32(windows.ERROR_SERVICE_NEVER_STARTED):
				default:
					tunnelError = syscall.Errno(notifier.ServiceStatus.Win32ExitCode)
				}
			}
		}
		if state != lastState {
			trackedTunnelsLock.Lock()
			trackedTunnels[tunnelName] = state
			trackedTunnelsLock.Unlock()
			IPCServerNotifyTunnelChange(tunnelName, state, tunnelError)
			lastState = state
		}
	}
}
