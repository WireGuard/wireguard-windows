/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"bufio"
	"fmt"
	"golang.zx2c4.com/winipcfg"
	"golang.zx2c4.com/wireguard/ipc"
	"log"
	"net"
	"runtime/debug"
	"strings"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/conf"
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

	defer func() {
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
	elog, err := eventlog.Open("WireGuard")
	if err != nil {
		exitCode = ERROR_LOG_CONTAINER_OPEN_FAILED
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
		elog.Error(1, "Unable to load configuration file from path "+service.path+": "+err.Error())
		exitCode = ERROR_OPEN_FAILED
		return
	}

	logger := &device.Logger{
		Debug: log.New(&confElogger{elog: elog, conf: conf, level: 1}, "", 0),
		Info:  log.New(&confElogger{elog: elog, conf: conf, level: 2}, "", 0),
		Error: log.New(&confElogger{elog: elog, conf: conf, level: 3}, "", 0),
	}

	logger.Info.Println("Starting wireguard-go version", device.WireGuardGoVersion)
	logger.Debug.Println("Debug log enabled")

	wintun, err := tun.CreateTUN(conf.Name)
	if err == nil {
		realInterfaceName, err2 := wintun.Name()
		if err2 == nil {
			conf.Name = realInterfaceName
		}
	} else {
		logger.Error.Println("Failed to create TUN device:", err)
		exitCode = ERROR_ADAP_HDW_ERR
		return
	}

	dev = device.NewDevice(wintun, logger)
	dev.Up()
	logger.Info.Println("Device started")

	uapi, err = ipc.UAPIListen(conf.Name)
	if err != nil {
		logger.Error.Println("Failed to listen on uapi socket:", err)
		exitCode = ERROR_PIPE_LISTENING
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
		logger.Error.Println("Failed to convert to UAPI serialization:", err)
		exitCode = ERROR_INVALID_PARAMETER
		return
	}
	dev.IpcSetOperation(bufio.NewReader(strings.NewReader(uapiConf)))
	guid := wintun.(*tun.NativeTun).GUID()

	routeChangeCallback, err = monitorDefaultRoutes(dev, conf.Interface.Mtu == 0, &guid)
	if err != nil {
		logger.Error.Println("Unable to bind sockets to default route:", err)
		exitCode = ERROR_NETWORK_BUSY
		return
	}

	err = configureInterface(conf, &guid)
	if err != nil {
		logger.Error.Println("Unable to set interface addresses, routes, DNS, or IP settings:", err)
		exitCode = ERROR_NETWORK_BUSY
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
				logger.Error.Printf("Unexpected service control request #%d", c)
			}
		case <-dev.Wait():
			return
		}
	}
}
