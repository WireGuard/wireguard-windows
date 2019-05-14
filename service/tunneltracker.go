/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

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
)

//sys notifyServiceStatusChange(service windows.Handle, notifyMask uint32, notifier *SERVICE_NOTIFY) (ret error) = advapi32.NotifyServiceStatusChangeW
//sys sleepEx(milliseconds uint32, alertable bool) (ret uint32) = kernel32.SleepEx

const (
	SERVICE_NOTIFY_STATUS_CHANGE    = 2
	SERVICE_NOTIFY_STOPPED          = 0x00000001
	SERVICE_NOTIFY_START_PENDING    = 0x00000002
	SERVICE_NOTIFY_STOP_PENDING     = 0x00000004
	SERVICE_NOTIFY_RUNNING          = 0x00000008
	SERVICE_NOTIFY_CONTINUE_PENDING = 0x00000010
	SERVICE_NOTIFY_PAUSE_PENDING    = 0x00000020
	SERVICE_NOTIFY_PAUSED           = 0x00000040
	SERVICE_NOTIFY_CREATED          = 0x00000080
	SERVICE_NOTIFY_DELETED          = 0x00000100
	SERVICE_NOTIFY_DELETE_PENDING   = 0x00000200

	STATUS_USER_APC    = 0x000000C0
	WAIT_IO_COMPLETION = STATUS_USER_APC
)

type SERVICE_NOTIFY struct {
	Version               uint32
	NotifyCallback        uintptr
	Context               uintptr
	NotificationStatus    uint32
	ServiceStatus         windows.SERVICE_STATUS_PROCESS
	NotificationTriggered uint32
	ServiceNames          *uint16
}

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

var serviceTrackerCallbackPtr = windows.NewCallback(func(notifier *SERVICE_NOTIFY) uintptr {
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

	const serviceNotifications = SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_START_PENDING | SERVICE_NOTIFY_STOP_PENDING | SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_DELETE_PENDING
	notifier := &SERVICE_NOTIFY{
		Version:        SERVICE_NOTIFY_STATUS_CHANGE,
		NotifyCallback: serviceTrackerCallbackPtr,
	}

	checkForDisabled := func() (shouldReturn bool) {
		config, err := service.Config()
		if err == syscall.Errno(serviceMARKED_FOR_DELETE) || config.StartType == windows.SERVICE_DISABLED {
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
		err := notifyServiceStatusChange(service.Handle, serviceNotifications, notifier)
		switch err {
		case nil:
			for {
				if sleepEx(uint32(time.Second*3/time.Millisecond), true) == WAIT_IO_COMPLETION {
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
				maybeErr := Error(notifier.ServiceStatus.ServiceSpecificExitCode)
				if maybeErr != ErrorSuccess {
					tunnelError = maybeErr
				}
			} else {
				switch notifier.ServiceStatus.Win32ExitCode {
				case uint32(windows.NO_ERROR), serviceNEVER_STARTED:
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
