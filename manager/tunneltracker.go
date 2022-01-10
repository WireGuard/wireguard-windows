/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/services"
)

var (
	trackedTunnels     = make(map[string]TunnelState)
	trackedTunnelsLock = sync.Mutex{}
)

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

var serviceTrackerCallbackPtr = windows.NewCallback(func(notifier *windows.SERVICE_NOTIFY) uintptr {
	return 0
})

type serviceSubscriptionState struct {
	service *mgr.Service
	cb      func(status uint32) bool
	done    sync.WaitGroup
	once    uint32
}

var serviceSubscriptionCallbackPtr = windows.NewCallback(func(notification uint32, context uintptr) uintptr {
	state := (*serviceSubscriptionState)(unsafe.Pointer(context))
	if atomic.LoadUint32(&state.once) != 0 {
		return 0
	}
	if notification == 0 {
		status, err := state.service.Query()
		if err == nil {
			notification = svcStateToNotifyState(uint32(status.State))
		}
	}
	if state.cb(notification) && atomic.CompareAndSwapUint32(&state.once, 0, 1) {
		state.done.Done()
	}
	return 0
})

func svcStateToNotifyState(s uint32) uint32 {
	switch s {
	case windows.SERVICE_STOPPED:
		return windows.SERVICE_NOTIFY_STOPPED
	case windows.SERVICE_START_PENDING:
		return windows.SERVICE_NOTIFY_START_PENDING
	case windows.SERVICE_STOP_PENDING:
		return windows.SERVICE_NOTIFY_STOP_PENDING
	case windows.SERVICE_RUNNING:
		return windows.SERVICE_NOTIFY_RUNNING
	case windows.SERVICE_CONTINUE_PENDING:
		return windows.SERVICE_NOTIFY_CONTINUE_PENDING
	case windows.SERVICE_PAUSE_PENDING:
		return windows.SERVICE_NOTIFY_PAUSE_PENDING
	case windows.SERVICE_PAUSED:
		return windows.SERVICE_NOTIFY_PAUSED
	case windows.SERVICE_NO_CHANGE:
		return 0
	default:
		return 0
	}
}

func notifyStateToTunState(s uint32) TunnelState {
	if s&(windows.SERVICE_NOTIFY_STOPPED|windows.SERVICE_NOTIFY_DELETED) != 0 {
		return TunnelStopped
	} else if s&(windows.SERVICE_NOTIFY_DELETE_PENDING|windows.SERVICE_NOTIFY_STOP_PENDING) != 0 {
		return TunnelStopping
	} else if s&windows.SERVICE_NOTIFY_RUNNING != 0 {
		return TunnelStarted
	} else if s&windows.SERVICE_NOTIFY_START_PENDING != 0 {
		return TunnelStarting
	} else {
		return TunnelUnknown
	}
}

func trackService(service *mgr.Service, callback func(status uint32) bool) error {
	var subscription uintptr
	state := &serviceSubscriptionState{service: service, cb: callback}
	state.done.Add(1)
	err := windows.SubscribeServiceChangeNotifications(service.Handle, windows.SC_EVENT_STATUS_CHANGE, serviceSubscriptionCallbackPtr, uintptr(unsafe.Pointer(state)), &subscription)
	if err == nil {
		defer windows.UnsubscribeServiceChangeNotifications(subscription)
		status, err := service.Query()
		if err == nil {
			if callback(svcStateToNotifyState(uint32(status.State))) {
				return nil
			}
		}
		state.done.Wait()
		runtime.KeepAlive(state.cb)
		return nil
	}
	if !errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
		return err
	}

	// TODO: Below this line is Windows 7 compatibility code, which hopefully we can delete at some point.

	runtime.LockOSThread()
	// This line would be fitting but is intentionally commented out:
	//
	//     defer runtime.UnlockOSThread()
	//
	// The reason is that NotifyServiceStatusChange used queued APC, which winds up messing
	// with the thread local context, which in turn appears to corrupt Go's own usage of TLS,
	// leading to crashes sometime later (usually in runtime_unlock()) when the thread is recycled.

	const serviceNotifications = windows.SERVICE_NOTIFY_RUNNING | windows.SERVICE_NOTIFY_START_PENDING | windows.SERVICE_NOTIFY_STOP_PENDING | windows.SERVICE_NOTIFY_STOPPED | windows.SERVICE_NOTIFY_DELETE_PENDING
	notifier := &windows.SERVICE_NOTIFY{
		Version:        windows.SERVICE_NOTIFY_STATUS_CHANGE,
		NotifyCallback: serviceTrackerCallbackPtr,
	}
	for {
		err := windows.NotifyServiceStatusChange(service.Handle, serviceNotifications, notifier)
		switch err {
		case nil:
			for {
				if windows.SleepEx(uint32(time.Second*3/time.Millisecond), true) == windows.WAIT_IO_COMPLETION {
					break
				} else if callback(0) {
					return nil
				}
			}
		case windows.ERROR_SERVICE_MARKED_FOR_DELETE:
			// Should be SERVICE_NOTIFY_DELETE_PENDING, but actually, we must release the handle and return here; otherwise it never deletes.
			if callback(windows.SERVICE_NOTIFY_DELETED) {
				return nil
			}
		case windows.ERROR_SERVICE_NOTIFY_CLIENT_LAGGING:
			continue
		default:
			return err
		}
		if callback(svcStateToNotifyState(notifier.ServiceStatus.CurrentState)) {
			return nil
		}
	}
}

func trackTunnelService(tunnelName string, service *mgr.Service) {
	trackedTunnelsLock.Lock()
	if _, found := trackedTunnels[tunnelName]; found {
		trackedTunnelsLock.Unlock()
		service.Close()
		return
	}

	defer func() {
		service.Close()
		log.Printf("[%s] Tunnel service tracker finished", tunnelName)
	}()
	trackedTunnels[tunnelName] = TunnelUnknown
	trackedTunnelsLock.Unlock()
	defer func() {
		trackedTunnelsLock.Lock()
		delete(trackedTunnels, tunnelName)
		trackedTunnelsLock.Unlock()
	}()

	for i := 0; i < 20; i++ {
		if i > 0 {
			time.Sleep(time.Second / 5)
		}
		if status, err := service.Query(); err != nil || status.State != svc.Stopped {
			break
		}
	}

	checkForDisabled := func() (shouldReturn bool) {
		config, err := service.Config()
		if err == windows.ERROR_SERVICE_MARKED_FOR_DELETE || (err != nil && config.StartType == windows.SERVICE_DISABLED) {
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
	lastState := TunnelUnknown
	err := trackService(service, func(status uint32) bool {
		state := notifyStateToTunState(status)
		var tunnelError error
		if state == TunnelStopped {
			serviceStatus, err := service.Query()
			if err == nil {
				if serviceStatus.Win32ExitCode == uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
					maybeErr := services.Error(serviceStatus.ServiceSpecificExitCode)
					if maybeErr != services.ErrorSuccess {
						tunnelError = maybeErr
					}
				} else {
					switch serviceStatus.Win32ExitCode {
					case uint32(windows.NO_ERROR), uint32(windows.ERROR_SERVICE_NEVER_STARTED):
					default:
						tunnelError = syscall.Errno(serviceStatus.Win32ExitCode)
					}
				}
			}
			if tunnelError != nil {
				service.Delete()
			}
		}
		if state != lastState {
			trackedTunnelsLock.Lock()
			trackedTunnels[tunnelName] = state
			trackedTunnelsLock.Unlock()
			IPCServerNotifyTunnelChange(tunnelName, state, tunnelError)
			lastState = state
		}
		if state == TunnelUnknown && checkForDisabled() {
			return true
		}
		return state == TunnelStopped
	})
	if err != nil && !checkForDisabled() {
		trackedTunnelsLock.Lock()
		trackedTunnels[tunnelName] = TunnelStopped
		trackedTunnelsLock.Unlock()
		IPCServerNotifyTunnelChange(tunnelName, TunnelStopped, fmt.Errorf("Unable to continue monitoring service, so stopping: %w", err))
		service.Control(svc.Stop)
	}
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
		trackedTunnelsLock.Lock()
		if _, found := trackedTunnels[name]; found {
			trackedTunnelsLock.Unlock()
			continue
		}
		trackedTunnelsLock.Unlock()
		serviceName, err := conf.ServiceNameOfTunnel(name)
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

var servicesSubscriptionWatcherCallbackPtr = windows.NewCallback(func(notification uint32, context uintptr) uintptr {
	trackExistingTunnels()
	return 0
})

func watchNewTunnelServices() error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	var subscription uintptr
	err = windows.SubscribeServiceChangeNotifications(m.Handle, windows.SC_EVENT_DATABASE_CHANGE, servicesSubscriptionWatcherCallbackPtr, 0, &subscription)
	if err == nil {
		// We probably could do:
		//     defer windows.UnsubscribeServiceChangeNotifications(subscription)
		// and then terminate after some point, but instead we just let this go forever; it's process-lived.
		return trackExistingTunnels()
	}
	if !errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
		return err
	}

	// TODO: Below this line is Windows 7 compatibility code, which hopefully we can delete at some point.
	go func() {
		runtime.LockOSThread()
		notifier := &windows.SERVICE_NOTIFY{
			Version:        windows.SERVICE_NOTIFY_STATUS_CHANGE,
			NotifyCallback: serviceTrackerCallbackPtr,
		}
		for {
			err := windows.NotifyServiceStatusChange(m.Handle, windows.SERVICE_NOTIFY_CREATED, notifier)
			if err == nil {
				windows.SleepEx(windows.INFINITE, true)
				if notifier.ServiceNames != nil {
					windows.LocalFree(windows.Handle(unsafe.Pointer(notifier.ServiceNames)))
					notifier.ServiceNames = nil
				}
				trackExistingTunnels()
			} else if err == windows.ERROR_SERVICE_NOTIFY_CLIENT_LAGGING {
				continue
			} else {
				time.Sleep(time.Second * 3)
				trackExistingTunnels()
			}
		}
	}()
	return trackExistingTunnels()
}
