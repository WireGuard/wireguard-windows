/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/conf"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

//sys notifyServiceStatusChange(service windows.Handle, notifyMask uint32, notifyBuffer uintptr) (status uint32) = advapi32.NotifyServiceStatusChangeW
//sys sleepEx(milliseconds uint32, alertable bool) (ret uint32, err error) = kernel32.SleepEx

const (
	serviceNotify_CREATED          uint32 = 0x00000080
	serviceNotify_CONTINUE_PENDING        = 0x00000010
	serviceNotify_DELETE_PENDING          = 0x00000200
	serviceNotify_DELETED                 = 0x00000100
	serviceNotify_PAUSE_PENDING           = 0x00000020
	serviceNotify_PAUSED                  = 0x00000040
	serviceNotify_RUNNING                 = 0x00000008
	serviceNotify_START_PENDING           = 0x00000002
	serviceNotify_STOP_PENDING            = 0x00000004
	serviceNotify_STOPPED                 = 0x00000001
)
const serviceNotify_STATUS_CHANGE uint32 = 2
const errorServiceMARKED_FOR_DELETE uint32 = 1072
const errorServiceNOTIFY_CLIENT_LAGGING uint32 = 1294

type serviceStatus struct {
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
	processId               uint32
	serviceFlags            uint32
}

type serviceNotify struct {
	version               uint32
	notifyCallback        uintptr
	context               uintptr
	notificationStatus    uint32
	serviceStatus         serviceStatus
	notificationTriggered uint32
	serviceNames          *uint16
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

var serviceTrackerCallbackPtr = windows.NewCallback(func(notifier *serviceNotify) uintptr {
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
	defer service.Close()

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

	const serviceNotifications = serviceNotify_RUNNING | serviceNotify_START_PENDING | serviceNotify_STOP_PENDING | serviceNotify_STOPPED | serviceNotify_DELETE_PENDING
	notifier := &serviceNotify{
		version:        serviceNotify_STATUS_CHANGE,
		notifyCallback: serviceTrackerCallbackPtr,
	}

	runtime.LockOSThread()
	lastState := TunnelUnknown
	for {
		ret := notifyServiceStatusChange(service.Handle, serviceNotifications, uintptr(unsafe.Pointer(notifier)))
		switch ret {
		case 0:
			sleepEx(windows.INFINITE, true)
		case errorServiceMARKED_FOR_DELETE:
			trackedTunnelsLock.Lock()
			trackedTunnels[tunnelName] = TunnelStopped
			trackedTunnelsLock.Unlock()
			IPCServerNotifyTunnelChange(tunnelName, TunnelStopped, nil)
			return
		case errorServiceNOTIFY_CLIENT_LAGGING:
			continue
		default:
			trackedTunnelsLock.Lock()
			trackedTunnels[tunnelName] = TunnelStopped
			trackedTunnelsLock.Unlock()
			IPCServerNotifyTunnelChange(tunnelName, TunnelStopped, fmt.Errorf("Unable to continue monitoring service, so stopping: %v", syscall.Errno(ret)))
			service.Control(svc.Stop)
			return
		}

		state := svcStateToTunState(svc.State(notifier.serviceStatus.currentState))
		var tunnelError error
		if state == TunnelStopped {
			if notifier.serviceStatus.win32ExitCode == uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
				maybeErr := Error(notifier.serviceStatus.serviceSpecificExitCode)
				if maybeErr != ErrorSuccess {
					tunnelError = maybeErr
				}
			} else {
				switch notifier.serviceStatus.win32ExitCode {
				case uint32(windows.NO_ERROR), serviceNEVER_STARTED:
				default:
					tunnelError = syscall.Errno(notifier.serviceStatus.win32ExitCode)
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
