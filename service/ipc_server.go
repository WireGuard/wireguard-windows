/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"bytes"
	"encoding/gob"
	"errors"
	"golang.zx2c4.com/wireguard/windows/conf"
	"net/rpc"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var managerServices = make(map[*ManagerService]bool)
var managerServicesLock sync.RWMutex
var haveQuit uint32
var quitManagersChan = make(chan struct{}, 1)

type ManagerService struct {
	events *os.File
}

func (s *ManagerService) StoredConfig(tunnelName string, config *conf.Config) error {
	c, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return err
	}
	*config = *c
	return nil
}

func (s *ManagerService) RuntimeConfig(tunnelName string, config *conf.Config) error {
	//TODO

	return nil
}

func (s *ManagerService) Start(tunnelName string, state *TunnelState) error {
	c, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return err
	}
	path, err := c.Path()
	if err != nil {
		return err
	}
	return InstallTunnel(path)
	//TODO: write out *state
}

func (s *ManagerService) Stop(tunnelName string, state *TunnelState) error {
	return UninstallTunnel(tunnelName)
	//TODO: This function should do nothing if the tunnel is already stopped
	//TODO: write out *state
}

func (s *ManagerService) Delete(tunnelName string, state *TunnelState) error {
	err := s.Stop(tunnelName, state)
	if err != nil {
		return err
	}
	//TODO: wait for stopped somehow
	if *state != TunnelStopped {
		return errors.New("Unable to stop tunnel before deleting")
	}
	return conf.DeleteName(tunnelName)
}

func (s *ManagerService) State(tunnelName string, state *TunnelState) error {
	//TODO

	return nil
}

func (s *ManagerService) Create(tunnelConfig conf.Config, tunnel *Tunnel) error {
	err := tunnelConfig.Save()
	if err != nil {
		return err
	}
	*tunnel = Tunnel{tunnelConfig.Name}
	return nil
	//TODO: handle already existing situation
	//TODO: handle already running and existing situation
}

func (s *ManagerService) Tunnels(unused uintptr, tunnels *[]Tunnel) error {
	names, err := conf.ListConfigNames()
	if err != nil {
		return err
	}
	*tunnels = make([]Tunnel, len(names))
	for i := 0; i < len(*tunnels); i++ {
		(*tunnels)[i].Name = names[i]
	}
	return nil
	//TODO: account for running ones that aren't in the configuration store somehow
}

func (s *ManagerService) Quit(stopTunnelsOnQuit bool, alreadyQuit *bool) error {
	if !atomic.CompareAndSwapUint32(&haveQuit, 0, 1) {
		*alreadyQuit = true
		return nil
	}
	*alreadyQuit = false

	// Work around potential race condition of delivering messages to the wrong process by removing from notifications.
	managerServicesLock.Lock()
	delete(managerServices, s)
	managerServicesLock.Unlock()

	if stopTunnelsOnQuit {
		names, err := conf.ListConfigNames()
		if err != nil {
			return err
		}
		for _, name := range names {
			UninstallTunnel(name)
		}
	}

	quitManagersChan <- struct{}{}
	return nil
}

func IPCServerListen(reader *os.File, writer *os.File, events *os.File) error {
	service := &ManagerService{events: events}

	server := rpc.NewServer()
	err := server.Register(service)
	if err != nil {
		return err
	}

	go func() {
		managerServicesLock.Lock()
		managerServices[service] = true
		managerServicesLock.Unlock()
		server.ServeConn(&pipeRWC{reader, writer})
		managerServicesLock.Lock()
		delete(managerServices, service)
		managerServicesLock.Unlock()

	}()
	return nil
}

func notifyAll(notificationType NotificationType, ifaces ...interface{}) {
	if len(managerServices) == 0 {
		return
	}

	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(notificationType)
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		err = encoder.Encode(iface)
		if err != nil {
			return
		}
	}

	managerServicesLock.RLock()
	for m := range managerServices {
		go func() {
			m.events.SetWriteDeadline(time.Now().Add(time.Second))
			m.events.Write(buf.Bytes())
		}()
	}
	managerServicesLock.RUnlock()
}

func IPCServerNotifyTunnelChange(name string, state TunnelState) {
	notifyAll(TunnelChangeNotificationType, name, state)
}

func IPCServerNotifyTunnelsChange() {
	notifyAll(TunnelsChangeNotificationType)
}
