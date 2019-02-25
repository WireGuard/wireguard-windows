/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"errors"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
	"net/rpc"
	"os"
	"sync"
	"sync/atomic"
)

var managerServices = make(map[*ManagerService]bool)
var managerServicesLock sync.RWMutex
var haveQuit uint32
var quitManagersChan = make(chan struct{}, 1)

type ManagerService struct {
	notifierHandles     map[windows.Handle]bool
	notifierHandlesLock sync.RWMutex
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

func (s *ManagerService) RegisterAsNotificationThread(handle windows.Handle, unused *uintptr) error {
	s.notifierHandlesLock.Lock()
	s.notifierHandles[handle] = true
	s.notifierHandlesLock.Unlock()
	return nil
}

func (s *ManagerService) UnregisterAsNotificationThread(handle windows.Handle, unused *uintptr) error {
	s.notifierHandlesLock.Lock()
	delete(s.notifierHandles, handle)
	s.notifierHandlesLock.Unlock()
	return nil
}

func IPCServerListen(reader *os.File, writer *os.File) error {
	service := &ManagerService{notifierHandles: make(map[windows.Handle]bool)}

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

//sys postMessage(hwnd windows.Handle, msg uint, wparam uintptr, lparam uintptr) (err error) = user32.PostMessageW

func notifyAll(f func(handle windows.Handle)) {
	managerServicesLock.RLock()
	for m, _ := range managerServices {
		m.notifierHandlesLock.RLock()
		for handle, _ := range m.notifierHandles {
			f(handle)
		}
		m.notifierHandlesLock.RUnlock()
	}
	managerServicesLock.RUnlock()
}

func IPCServerNotifyTunnelChange(name string) {
	notifyAll(func(handle windows.Handle) {
		//TODO: postthreadmessage
	})
}

func IPCServerNotifyTunnelsChange() {
	notifyAll(func(handle windows.Handle) {
		postMessage(handle, tunnelsChangedMessage, 0, 0)
	})
}
