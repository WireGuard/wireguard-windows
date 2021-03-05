/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"net"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/winpipe"

	"golang.zx2c4.com/wireguard/windows/services"
)

type connectedTunnel struct {
	net.Conn
	sync.Mutex
}

var connectedTunnelServicePipes = make(map[string]*connectedTunnel)
var connectedTunnelServicePipesLock sync.RWMutex

func connectTunnelServicePipe(tunnelName string) (*connectedTunnel, error) {
	connectedTunnelServicePipesLock.RLock()
	pipe, ok := connectedTunnelServicePipes[tunnelName]
	if ok {
		pipe.Lock()
		connectedTunnelServicePipesLock.RUnlock()
		return pipe, nil
	}
	connectedTunnelServicePipesLock.RUnlock()
	connectedTunnelServicePipesLock.Lock()
	defer connectedTunnelServicePipesLock.Unlock()
	pipe, ok = connectedTunnelServicePipes[tunnelName]
	if ok {
		pipe.Lock()
		return pipe, nil
	}
	pipePath, err := services.PipePathOfTunnel(tunnelName)
	if err != nil {
		return nil, err
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	pipe = &connectedTunnel{}
	pipe.Conn, err = winpipe.Dial(pipePath, nil, &winpipe.DialConfig{ExpectedOwner: localSystem})
	if err != nil {
		return nil, err
	}
	connectedTunnelServicePipes[tunnelName] = pipe
	pipe.Lock()
	return pipe, nil
}

func disconnectTunnelServicePipe(tunnelName string) {
	connectedTunnelServicePipesLock.Lock()
	defer connectedTunnelServicePipesLock.Unlock()
	pipe, ok := connectedTunnelServicePipes[tunnelName]
	if !ok {
		return
	}
	pipe.Lock()
	pipe.Close()
	delete(connectedTunnelServicePipes, tunnelName)
	pipe.Unlock()
}
