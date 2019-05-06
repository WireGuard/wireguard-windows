/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"encoding/gob"
	"errors"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/updater"
	"net/rpc"
	"os"
)

type Tunnel struct {
	Name string
}

type TunnelState int

const (
	TunnelUnknown TunnelState = iota
	TunnelStarted
	TunnelStopped
	TunnelStarting
	TunnelStopping
)

type NotificationType int

const (
	TunnelChangeNotificationType NotificationType = iota
	TunnelsChangeNotificationType
	ManagerStoppingNotificationType
	UpdateFoundNotificationType
	UpdateProgressNotificationType
)

var rpcClient *rpc.Client

type TunnelChangeCallback struct {
	cb func(tunnel *Tunnel, state TunnelState, globalState TunnelState, err error)
}

var tunnelChangeCallbacks = make(map[*TunnelChangeCallback]bool)

type TunnelsChangeCallback struct {
	cb func()
}

var tunnelsChangeCallbacks = make(map[*TunnelsChangeCallback]bool)

type ManagerStoppingCallback struct {
	cb func()
}

var managerStoppingCallbacks = make(map[*ManagerStoppingCallback]bool)

type UpdateFoundCallback struct {
	cb func(updateState UpdateState)
}

var updateFoundCallbacks = make(map[*UpdateFoundCallback]bool)

type UpdateProgressCallback struct {
	cb func(dp updater.DownloadProgress)
}

var updateProgressCallbacks = make(map[*UpdateProgressCallback]bool)

func InitializeIPCClient(reader *os.File, writer *os.File, events *os.File) {
	rpcClient = rpc.NewClient(&pipeRWC{reader, writer})
	go func() {
		decoder := gob.NewDecoder(events)
		for {
			var notificationType NotificationType
			err := decoder.Decode(&notificationType)
			if err != nil {
				return
			}
			switch notificationType {
			case TunnelChangeNotificationType:
				var tunnel string
				err := decoder.Decode(&tunnel)
				if err != nil || len(tunnel) == 0 {
					continue
				}
				var state TunnelState
				err = decoder.Decode(&state)
				if err != nil {
					continue
				}
				var globalState TunnelState
				err = decoder.Decode(&globalState)
				if err != nil {
					continue
				}
				var errStr string
				err = decoder.Decode(&errStr)
				if err != nil {
					continue
				}
				var retErr error
				if len(errStr) > 0 {
					retErr = errors.New(errStr)
				}
				if state == TunnelUnknown {
					continue
				}
				t := &Tunnel{tunnel}
				for cb := range tunnelChangeCallbacks {
					cb.cb(t, state, globalState, retErr)
				}
			case TunnelsChangeNotificationType:
				for cb := range tunnelsChangeCallbacks {
					cb.cb()
				}
			case ManagerStoppingNotificationType:
				for cb := range managerStoppingCallbacks {
					cb.cb()
				}
			case UpdateFoundNotificationType:
				var state UpdateState
				err = decoder.Decode(&state)
				if err != nil {
					continue
				}
				for cb := range updateFoundCallbacks {
					cb.cb(state)
				}
			case UpdateProgressNotificationType:
				var dp updater.DownloadProgress
				err = decoder.Decode(&dp.Activity)
				if err != nil {
					continue
				}
				err = decoder.Decode(&dp.BytesDownloaded)
				if err != nil {
					continue
				}
				err = decoder.Decode(&dp.BytesTotal)
				if err != nil {
					continue
				}
				var errStr string
				err = decoder.Decode(&errStr)
				if err != nil {
					continue
				}
				if len(errStr) > 0 {
					dp.Error = errors.New(errStr)
				}
				err = decoder.Decode(&dp.Complete)
				if err != nil {
					continue
				}
				for cb := range updateProgressCallbacks {
					cb.cb(dp)
				}
			}
		}
	}()
}

func (t *Tunnel) StoredConfig() (c conf.Config, err error) {
	err = rpcClient.Call("ManagerService.StoredConfig", t.Name, &c)
	return
}

func (t *Tunnel) RuntimeConfig() (c conf.Config, err error) {
	err = rpcClient.Call("ManagerService.RuntimeConfig", t.Name, &c)
	return
}

func (t *Tunnel) Start() error {
	return rpcClient.Call("ManagerService.Start", t.Name, nil)
}

func (t *Tunnel) Stop() error {
	return rpcClient.Call("ManagerService.Stop", t.Name, nil)
}

func (t *Tunnel) Toggle() (oldState TunnelState, err error) {
	oldState, err = t.State()
	if err != nil {
		oldState = TunnelUnknown
		return
	}
	if oldState == TunnelStarted {
		err = t.Stop()
	} else if oldState == TunnelStopped {
		err = t.Start()
	}
	return
}

func (t *Tunnel) WaitForStop() error {
	return rpcClient.Call("ManagerService.WaitForStop", t.Name, nil)
}

func (t *Tunnel) Delete() error {
	return rpcClient.Call("ManagerService.Delete", t.Name, nil)
}

func (t *Tunnel) State() (TunnelState, error) {
	var state TunnelState
	return state, rpcClient.Call("ManagerService.State", t.Name, &state)
}

func IPCClientNewTunnel(conf *conf.Config) (Tunnel, error) {
	var tunnel Tunnel
	return tunnel, rpcClient.Call("ManagerService.Create", *conf, &tunnel)
}

func IPCClientTunnels() ([]Tunnel, error) {
	var tunnels []Tunnel
	return tunnels, rpcClient.Call("ManagerService.Tunnels", uintptr(0), &tunnels)
}

func IPCClientGlobalState() (TunnelState, error) {
	var state TunnelState
	return state, rpcClient.Call("ManagerService.GlobalState", uintptr(0), &state)
}

func IPCClientQuit(stopTunnelsOnQuit bool) (bool, error) {
	var alreadyQuit bool
	return alreadyQuit, rpcClient.Call("ManagerService.Quit", stopTunnelsOnQuit, &alreadyQuit)
}

func IPCClientUpdateState() (UpdateState, error) {
	var state UpdateState
	return state, rpcClient.Call("ManagerService.UpdateState", uintptr(0), &state)
}

func IPCClientUpdate() error {
	return rpcClient.Call("ManagerService.Update", uintptr(0), nil)
}

func IPCClientRegisterTunnelChange(cb func(tunnel *Tunnel, state TunnelState, globalState TunnelState, err error)) *TunnelChangeCallback {
	s := &TunnelChangeCallback{cb}
	tunnelChangeCallbacks[s] = true
	return s
}
func (cb *TunnelChangeCallback) Unregister() {
	delete(tunnelChangeCallbacks, cb)
}
func IPCClientRegisterTunnelsChange(cb func()) *TunnelsChangeCallback {
	s := &TunnelsChangeCallback{cb}
	tunnelsChangeCallbacks[s] = true
	return s
}
func (cb *TunnelsChangeCallback) Unregister() {
	delete(tunnelsChangeCallbacks, cb)
}
func IPCClientRegisterManagerStopping(cb func()) *ManagerStoppingCallback {
	s := &ManagerStoppingCallback{cb}
	managerStoppingCallbacks[s] = true
	return s
}
func (cb *ManagerStoppingCallback) Unregister() {
	delete(managerStoppingCallbacks, cb)
}
func IPCClientRegisterUpdateFound(cb func(updateState UpdateState)) *UpdateFoundCallback {
	s := &UpdateFoundCallback{cb}
	updateFoundCallbacks[s] = true
	return s
}
func (cb *UpdateFoundCallback) Unregister() {
	delete(updateFoundCallbacks, cb)
}
func IPCClientRegisterUpdateProgress(cb func(dp updater.DownloadProgress)) *UpdateProgressCallback {
	s := &UpdateProgressCallback{cb}
	updateProgressCallbacks[s] = true
	return s
}
func (cb *UpdateProgressCallback) Unregister() {
	delete(updateProgressCallbacks, cb)
}
