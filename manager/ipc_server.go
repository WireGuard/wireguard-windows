/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"net/rpc"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"golang.zx2c4.com/wireguard/ipc/winpipe"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/updater"
)

var managerServices = make(map[*ManagerService]bool)
var managerServicesLock sync.RWMutex
var haveQuit uint32
var quitManagersChan = make(chan struct{}, 1)

type ManagerService struct {
	events        *os.File
	elevatedToken windows.Token
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
	storedConfig, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return err
	}
	pipePath, err := services.PipePathOfTunnel(storedConfig.Name)
	if err != nil {
		return err
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	pipe, err := winpipe.DialPipe(pipePath, nil, localSystem)
	if err != nil {
		return err
	}
	defer pipe.Close()
	pipe.SetWriteDeadline(time.Now().Add(time.Second * 2))
	_, err = pipe.Write([]byte("get=1\n\n"))
	if err != nil {
		return err
	}
	pipe.SetReadDeadline(time.Now().Add(time.Second * 2))
	resp, err := ioutil.ReadAll(pipe)
	if err != nil {
		return err
	}
	runtimeConfig, err := conf.FromUAPI(string(resp), storedConfig)
	if err != nil {
		return err
	}
	*config = *runtimeConfig
	return nil
}

func (s *ManagerService) Start(tunnelName string, unused *uintptr) error {
	// For now, enforce only one tunnel at a time. Later we'll remove this silly restriction.
	trackedTunnelsLock.Lock()
	tt := make([]string, 0, len(trackedTunnels))
	var inTransition string
	for t, state := range trackedTunnels {
		tt = append(tt, t)
		if len(t) > 0 && (state == TunnelStarting || state == TunnelUnknown) {
			inTransition = t
			break
		}
	}
	trackedTunnelsLock.Unlock()
	if len(inTransition) != 0 {
		return fmt.Errorf("Please allow the tunnel ‘%s’ to finish activating", inTransition)
	}
	go func() {
		for _, t := range tt {
			s.Stop(t, unused)
		}
		for _, t := range tt {
			var state TunnelState
			var unused uintptr
			if s.State(t, &state) == nil && (state == TunnelStarted || state == TunnelStarting) {
				log.Printf("[%s] Trying again to stop zombie tunnel", t)
				s.Stop(t, &unused)
				time.Sleep(time.Millisecond * 100)
			}
		}
	}()
	time.AfterFunc(time.Second*10, cleanupStaleWintunInterfaces)

	// After that process is started -- it's somewhat asynchronous -- we install the new one.
	c, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return err
	}
	path, err := c.Path()
	if err != nil {
		return err
	}
	return InstallTunnel(path)
}

func (s *ManagerService) Stop(tunnelName string, _ *uintptr) error {
	time.AfterFunc(time.Second*10, cleanupStaleWintunInterfaces)

	err := UninstallTunnel(tunnelName)
	if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		_, notExistsError := conf.LoadFromName(tunnelName)
		if notExistsError == nil {
			return nil
		}
	}
	return err
}

func (s *ManagerService) WaitForStop(tunnelName string, _ *uintptr) error {
	serviceName, err := services.ServiceNameOfTunnel(tunnelName)
	if err != nil {
		return err
	}
	m, err := serviceManager()
	if err != nil {
		return err
	}
	for {
		service, err := m.OpenService(serviceName)
		if err == nil || err == windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			service.Close()
			time.Sleep(time.Second / 3)
		} else {
			return nil
		}
	}
}

func (s *ManagerService) Delete(tunnelName string, _ *uintptr) error {
	err := s.Stop(tunnelName, nil)
	if err != nil {
		return err
	}
	return conf.DeleteName(tunnelName)
}

func (s *ManagerService) State(tunnelName string, state *TunnelState) error {
	serviceName, err := services.ServiceNameOfTunnel(tunnelName)
	if err != nil {
		return err
	}
	m, err := serviceManager()
	if err != nil {
		return err
	}
	service, err := m.OpenService(serviceName)
	if err != nil {
		*state = TunnelStopped
		return nil
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		*state = TunnelUnknown
		return err
	}
	switch status.State {
	case svc.Stopped:
		*state = TunnelStopped
	case svc.StopPending:
		*state = TunnelStopping
	case svc.Running:
		*state = TunnelStarted
	case svc.StartPending:
		*state = TunnelStarting
	default:
		*state = TunnelUnknown
	}
	return nil
}

func (s *ManagerService) GlobalState(_ uintptr, state *TunnelState) error {
	*state = trackedTunnelsGlobalState()
	return nil
}

func (s *ManagerService) Create(tunnelConfig conf.Config, tunnel *Tunnel) error {
	err := tunnelConfig.Save()
	if err != nil {
		return err
	}
	*tunnel = Tunnel{tunnelConfig.Name}
	return nil
	// TODO: handle already existing situation
	// TODO: handle already running and existing situation
}

func (s *ManagerService) Tunnels(_ uintptr, tunnels *[]Tunnel) error {
	names, err := conf.ListConfigNames()
	if err != nil {
		return err
	}
	*tunnels = make([]Tunnel, len(names))
	for i := 0; i < len(*tunnels); i++ {
		(*tunnels)[i].Name = names[i]
	}
	return nil
	// TODO: account for running ones that aren't in the configuration store somehow
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

func (s *ManagerService) UpdateState(_ uintptr, state *UpdateState) error {
	*state = updateState
	return nil
}

func (s *ManagerService) Update(_ uintptr, _ *uintptr) error {
	progress := updater.DownloadVerifyAndExecute(uintptr(s.elevatedToken))
	go func() {
		for {
			dp := <-progress
			IPCServerNotifyUpdateProgress(dp)
			if dp.Complete || dp.Error != nil {
				return
			}
		}
	}()
	return nil
}

func IPCServerListen(reader *os.File, writer *os.File, events *os.File, elevatedToken windows.Token) error {
	service := &ManagerService{
		events:        events,
		elevatedToken: elevatedToken,
	}

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
		m.events.SetWriteDeadline(time.Now().Add(time.Second))
		m.events.Write(buf.Bytes())
	}
	managerServicesLock.RUnlock()
}

func IPCServerNotifyTunnelChange(name string, state TunnelState, err error) {
	if err == nil {
		notifyAll(TunnelChangeNotificationType, name, state, trackedTunnelsGlobalState(), "")
	} else {
		notifyAll(TunnelChangeNotificationType, name, state, trackedTunnelsGlobalState(), err.Error())
	}
}

func IPCServerNotifyTunnelsChange() {
	notifyAll(TunnelsChangeNotificationType)
}

func IPCServerNotifyUpdateFound(state UpdateState) {
	notifyAll(UpdateFoundNotificationType, state)
}

func IPCServerNotifyUpdateProgress(dp updater.DownloadProgress) {
	if dp.Error == nil {
		notifyAll(UpdateProgressNotificationType, dp.Activity, dp.BytesDownloaded, dp.BytesTotal, "", dp.Complete)
	} else {
		notifyAll(UpdateProgressNotificationType, dp.Activity, dp.BytesDownloaded, dp.BytesTotal, dp.Error.Error(), dp.Complete)
	}
}

func IPCServerNotifyManagerStopping() {
	notifyAll(ManagerStoppingNotificationType)
	time.Sleep(time.Millisecond * 200)
}
