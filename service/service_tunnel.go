/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.zx2c4.com/winipcfg"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/conf"
	"log"
	"net"
	"runtime/debug"
	"strings"
)

type confElogger struct {
	elog  *eventlog.Log
	conf  *conf.Config
	level int
}

func (elog confElogger) Write(p []byte) (n int, err error) {
	msg := elog.conf.Name + ": " + string(p)
	n = len(msg)
	switch elog.level {
	case 1, 2:
		err = elog.elog.Info(1, msg)
	case 3:
		err = elog.elog.Error(1, msg)
	}
	return
}

type tunnelService struct {
	path string
}

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var dev *device.Device
	var uapi net.Listener
	var routeChangeCallback *winipcfg.RouteChangeCallback
	var elog *eventlog.Log
	var logger *device.Logger
	var err error
	serviceError := ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = determineErrorCode(err, serviceError)
		logErr := combineErrors(err, serviceError)
		if logErr != nil {
			if logger != nil {
				logger.Error.Println(logErr.Error())
			} else if elog != nil {
				elog.Error(1, logErr.Error())
			} else {
				fmt.Println(logErr.Error())
			}
		}
		changes <- svc.Status{State: svc.StopPending}
		if routeChangeCallback != nil {
			routeChangeCallback.Unregister()
		}
		if uapi != nil {
			uapi.Close()
		}
		if dev != nil {
			dev.Close()
		}
		if elog != nil {
			elog.Info(1, "Shutting down")
		}
	}()

	//TODO: remember to clean this up in the msi uninstaller
	eventlog.InstallAsEventCreate("WireGuard", eventlog.Info|eventlog.Warning|eventlog.Error)
	elog, err = eventlog.Open("WireGuard")
	if err != nil {
		serviceError = ErrorEventlogOpen
		return
	}
	log.SetOutput(elogger{elog})
	defer func() {
		if x := recover(); x != nil {
			elog.Error(1, fmt.Sprintf("%v:\n%s", x, string(debug.Stack())))
			panic(x)
		}
	}()

	conf, err := conf.LoadFromPath(service.path)
	if err != nil {
		serviceError = ErrorLoadConfiguration
		return
	}

	logger = &device.Logger{
		Debug: log.New(&confElogger{elog: elog, conf: conf, level: 1}, "", 0),
		Info:  log.New(&confElogger{elog: elog, conf: conf, level: 2}, "", 0),
		Error: log.New(&confElogger{elog: elog, conf: conf, level: 3}, "", 0),
	}

	logger.Info.Println("Starting wireguard-go version", device.WireGuardGoVersion)
	logger.Debug.Println("Debug log enabled")

	wintun, err := tun.CreateTUN(conf.Name)
	if err != nil {
		serviceError = ErrorCreateWintun
		return
	}
	realInterfaceName, err := wintun.Name()
	if err != nil {
		serviceError = ErrorDetermineWintunName
		return
	}
	conf.Name = realInterfaceName

	dev = device.NewDevice(wintun, logger)
	dev.Up()
	logger.Info.Println("Device started")

	uapi, err = ipc.UAPIListen(conf.Name)
	if err != nil {
		serviceError = ErrorUAPIListen
		return
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				continue
			}
			go dev.IpcHandle(conn)
		}
	}()
	logger.Info.Println("UAPI listener started")

	uapiConf, err := conf.ToUAPI()
	if err != nil {
		serviceError = ErrorUAPISerialization
		return
	}
	ipcErr := dev.IpcSetOperation(bufio.NewReader(strings.NewReader(uapiConf)))
	if ipcErr != nil {
		err = ipcErr
		serviceError = ErrorDeviceSetConfig
		return
	}

	guid := wintun.(*tun.NativeTun).GUID()

	routeChangeCallback, err = monitorDefaultRoutes(dev, conf.Interface.Mtu == 0, &guid)
	if err != nil {
		serviceError = ErrorBindSocketsToDefaultRoutes
		return
	}

	err = configureInterface(conf, &guid)
	if err != nil {
		serviceError = ErrorSetNetConfig
		return
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop:
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				logger.Error.Printf("Unexpected service control request #%d\n", c)
			}
		case <-dev.Wait():
			return
		}
	}
}
