/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
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
	TunnelDeleting
)

var rpcClient *rpc.Client

func InitializeIPCClient(reader *os.File, writer *os.File) {
	rpcClient = rpc.NewClient(&pipeRWC{reader, writer})
}

func (t *Tunnel) StoredConfig() (c conf.Config, err error) {
	err = rpcClient.Call("ManagerService.StoredConfig", t.Name, &c)
	return
}

func (t *Tunnel) RuntimeConfig() (c conf.Config, err error) {
	err = rpcClient.Call("ManagerService.RuntimeConfig", t.Name, &c)
	return
}

func (t *Tunnel) Start() (TunnelState, error) {
	var state TunnelState
	return state, rpcClient.Call("ManagerService.Start", t.Name, &state)
}

func (t *Tunnel) Stop() (TunnelState, error) {
	var state TunnelState
	return state, rpcClient.Call("ManagerService.Stop", t.Name, &state)
}

func (t *Tunnel) Delete() (TunnelState, error) {
	var state TunnelState
	return state, rpcClient.Call("ManagerService.Delete", t.Name, &state)
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
	return tunnels, rpcClient.Call("ManagerService.Tunnels", 0, &tunnels)
}

func IPCClientQuit(stopTunnelsOnQuit bool) (bool, error) {
	var alreadyQuit bool
	return alreadyQuit, rpcClient.Call("ManagerService.Quit", stopTunnelsOnQuit, &alreadyQuit)
}

func IPCClientRegisterAsNotificationThread() error {
	return rpcClient.Call("ManagerService.RegisterAsNotificationThread", windows.GetCurrentThreadId(), nil)
}

func IPCClientUnregisterAsNotificationThread() error {
	return rpcClient.Call("ManagerService.UnregisterAsNotificationThread", windows.GetCurrentThreadId(), nil)
}
