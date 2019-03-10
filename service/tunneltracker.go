/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/conf"
	"runtime"
	"syscall"
	"unsafe"
)

//sys notifyServiceStatusChange(service windows.Handle, notifyMask uint32, notifyBuffer uintptr) (err error) [failretval!=0] = advapi32.NotifyServiceStatusChangeW
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

type serviceNotify struct {
	version                 uint32
	notifyCallback          uintptr
	context                 uintptr
	notificationStatus      uint32
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
	processId               uint32
	serviceFlags            uint32
	notificationTriggered   uint32
	serviceNames            *uint16
}

func serviceTrackerCallback(notifier *serviceNotify) uintptr {
	return 0
}

var serviceTrackerCallbackPtr uintptr

func init() {
	serviceTrackerCallbackPtr = windows.NewCallback(serviceTrackerCallback)
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

func trackTunnelService(tunnelName string, svc *mgr.Service) {
	runtime.LockOSThread()
	const serviceNotifications = serviceNotify_RUNNING | serviceNotify_START_PENDING | serviceNotify_STOP_PENDING | serviceNotify_STOPPED | serviceNotify_DELETE_PENDING
	notifier := &serviceNotify{
		version:        serviceNotify_STATUS_CHANGE,
		notifyCallback: serviceTrackerCallbackPtr,
	}
	defer svc.Close()

	// This hasStopped ugliness is because Windows 7 will send a STOP_PENDING after it has already sent a STOPPED
	hasStopped := false

	for {
		notifier.context = 0
		err := notifyServiceStatusChange(svc.Handle, serviceNotifications, uintptr(unsafe.Pointer(notifier)))
		if err != nil {
			return
		}
		sleepEx(windows.INFINITE, true)
		if notifier.notificationStatus != 0 {
			return
		}
		var tunnelError error
		state := TunnelUnknown
		if notifier.notificationTriggered&serviceNotify_DELETE_PENDING != 0 {
			state = TunnelDeleting
		} else if notifier.notificationTriggered&serviceNotify_STOPPED != 0 {
			state = TunnelStopped
			hasStopped = true
			if notifier.win32ExitCode == uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
				maybeErr := Error(notifier.serviceSpecificExitCode)
				if maybeErr != ErrorSuccess {
					tunnelError = maybeErr
				}
			} else if notifier.win32ExitCode != uint32(windows.NO_ERROR) {
				tunnelError = syscall.Errno(notifier.win32ExitCode)
			}
		} else if notifier.notificationTriggered&serviceNotify_STOP_PENDING != 0 && hasStopped {
			state = TunnelStopping
		} else if notifier.notificationTriggered&serviceNotify_RUNNING != 0 {
			state = TunnelStarted
			hasStopped = false
		} else if notifier.notificationTriggered&serviceNotify_START_PENDING != 0 {
			state = TunnelStarting
			hasStopped = false
		}
		IPCServerNotifyTunnelChange(tunnelName, state, tunnelError)
		if state == TunnelDeleting {
			return
		}
	}
}
