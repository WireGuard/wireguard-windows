/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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

func (s *ManagerService) StoredConfig(tunnelName string) (*conf.Config, error) {
	return conf.LoadFromName(tunnelName)
}

func (s *ManagerService) RuntimeConfig(tunnelName string) (*conf.Config, error) {
	storedConfig, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return nil, err
	}
	pipePath, err := services.PipePathOfTunnel(storedConfig.Name)
	if err != nil {
		return nil, err
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	pipe, err := winpipe.DialPipe(pipePath, nil, localSystem)
	if err != nil {
		return nil, err
	}
	defer pipe.Close()
	pipe.SetWriteDeadline(time.Now().Add(time.Second * 2))
	_, err = pipe.Write([]byte("get=1\n\n"))
	if err != nil {
		return nil, err
	}
	pipe.SetReadDeadline(time.Now().Add(time.Second * 2))
	resp, err := ioutil.ReadAll(pipe)
	if err != nil {
		return nil, err
	}
	return conf.FromUAPI(string(resp), storedConfig)
}

func (s *ManagerService) Start(tunnelName string) error {
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
			s.Stop(t)
		}
		for _, t := range tt {
			state, err := s.State(t)
			if err == nil && (state == TunnelStarted || state == TunnelStarting) {
				log.Printf("[%s] Trying again to stop zombie tunnel", t)
				s.Stop(t)
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

func (s *ManagerService) Stop(tunnelName string) error {
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

func (s *ManagerService) WaitForStop(tunnelName string) error {
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

func (s *ManagerService) Delete(tunnelName string) error {
	err := s.Stop(tunnelName)
	if err != nil {
		return err
	}
	return conf.DeleteName(tunnelName)
}

func (s *ManagerService) State(tunnelName string) (TunnelState, error) {
	serviceName, err := services.ServiceNameOfTunnel(tunnelName)
	if err != nil {
		return 0, err
	}
	m, err := serviceManager()
	if err != nil {
		return 0, err
	}
	service, err := m.OpenService(serviceName)
	if err != nil {
		return TunnelStopped, nil
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return TunnelUnknown, nil
	}
	switch status.State {
	case svc.Stopped:
		return TunnelStopped, nil
	case svc.StopPending:
		return TunnelStopping, nil
	case svc.Running:
		return TunnelStarted, nil
	case svc.StartPending:
		return TunnelStarting, nil
	default:
		return TunnelUnknown, nil
	}
}

func (s *ManagerService) GlobalState() TunnelState {
	return trackedTunnelsGlobalState()
}

func (s *ManagerService) Create(tunnelConfig *conf.Config) (*Tunnel, error) {
	err := tunnelConfig.Save()
	if err != nil {
		return nil, err
	}
	return &Tunnel{tunnelConfig.Name}, nil
	// TODO: handle already existing situation
	// TODO: handle already running and existing situation
}

func (s *ManagerService) Tunnels() ([]Tunnel, error) {
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil, err
	}
	tunnels := make([]Tunnel, len(names))
	for i := 0; i < len(tunnels); i++ {
		(tunnels)[i].Name = names[i]
	}
	return tunnels, nil
	// TODO: account for running ones that aren't in the configuration store somehow
}

func (s *ManagerService) Quit(stopTunnelsOnQuit bool) (alreadyQuit bool, err error) {
	if !atomic.CompareAndSwapUint32(&haveQuit, 0, 1) {
		return true, nil
	}

	// Work around potential race condition of delivering messages to the wrong process by removing from notifications.
	managerServicesLock.Lock()
	delete(managerServices, s)
	managerServicesLock.Unlock()

	if stopTunnelsOnQuit {
		names, err := conf.ListConfigNames()
		if err != nil {
			return false, err
		}
		for _, name := range names {
			UninstallTunnel(name)
		}
	}

	quitManagersChan <- struct{}{}
	return false, nil
}

func (s *ManagerService) UpdateState() UpdateState {
	return updateState
}

func (s *ManagerService) Update() {
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
}

func (s *ManagerService) ServeConn(reader io.Reader, writer io.Writer) {
	decoder := gob.NewDecoder(reader)
	encoder := gob.NewEncoder(writer)
	for {
		var methodType MethodType
		err := decoder.Decode(&methodType)
		if err != nil {
			return
		}
		switch methodType {
		case StoredConfigMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			config, retErr := s.StoredConfig(tunnelName)
			err = encoder.Encode(*config)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case RuntimeConfigMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			config, retErr := s.RuntimeConfig(tunnelName)
			err = encoder.Encode(*config)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StartMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Start(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StopMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Stop(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case WaitForStopMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.WaitForStop(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case DeleteMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Delete(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StateMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			state, retErr := s.State(tunnelName)
			err = encoder.Encode(state)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case GlobalStateMethodType:
			state := s.GlobalState()
			err = encoder.Encode(state)
			if err != nil {
				return
			}
		case CreateMethodType:
			var config conf.Config
			err := decoder.Decode(&config)
			if err != nil {
				return
			}
			tunnel, retErr := s.Create(&config)
			err = encoder.Encode(tunnel)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case TunnelsMethodType:
			tunnels, retErr := s.Tunnels()
			err = encoder.Encode(tunnels)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case QuitMethodType:
			var stopTunnelsOnQuit bool
			err := decoder.Decode(&stopTunnelsOnQuit)
			if err != nil {
				return
			}
			alreadyQuit, retErr := s.Quit(stopTunnelsOnQuit)
			err = encoder.Encode(alreadyQuit)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case UpdateStateMethodType:
			updateState := s.UpdateState()
			err = encoder.Encode(updateState)
			if err != nil {
				return
			}
		case UpdateMethodType:
			s.Update()
		default:
			return
		}
	}
}

func IPCServerListen(reader *os.File, writer *os.File, events *os.File, elevatedToken windows.Token) {
	service := &ManagerService{
		events:        events,
		elevatedToken: elevatedToken,
	}

	go func() {
		defer printPanic()
		managerServicesLock.Lock()
		managerServices[service] = true
		managerServicesLock.Unlock()
		service.ServeConn(reader, writer)
		managerServicesLock.Lock()
		delete(managerServices, service)
		managerServicesLock.Unlock()

	}()
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

func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func IPCServerNotifyTunnelChange(name string, state TunnelState, err error) {
	notifyAll(TunnelChangeNotificationType, name, state, trackedTunnelsGlobalState(), errToString(err))
}

func IPCServerNotifyTunnelsChange() {
	notifyAll(TunnelsChangeNotificationType)
}

func IPCServerNotifyUpdateFound(state UpdateState) {
	notifyAll(UpdateFoundNotificationType, state)
}

func IPCServerNotifyUpdateProgress(dp updater.DownloadProgress) {
	notifyAll(UpdateProgressNotificationType, dp.Activity, dp.BytesDownloaded, dp.BytesTotal, errToString(dp.Error), dp.Complete)
}

func IPCServerNotifyManagerStopping() {
	notifyAll(ManagerStoppingNotificationType)
	time.Sleep(time.Millisecond * 200)
}
