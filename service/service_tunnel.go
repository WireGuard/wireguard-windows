/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/winipcfg"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
)

type tunnelService struct {
	path string
}

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var dev *device.Device
	var uapi net.Listener
	var routeChangeCallback *winipcfg.RouteChangeCallback
	var logger *device.Logger
	var err error
	serviceError := ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = determineErrorCode(err, serviceError)
		logErr := combineErrors(err, serviceError)
		logIt := func(a ...interface{}) {
			if logger != nil {
				logger.Error.Println(a...)
			} else {
				log.Println(a...)
			}
		}
		if logErr != nil {
			logIt(logErr)
		}
		changes <- svc.Status{State: svc.StopPending}

		stopIt := make(chan bool, 1)
		go func() {
			t := time.NewTicker(time.Second * 30)
			for {
				select {
				case <-t.C:
					t.Stop()
					buf := make([]byte, 1024)
					for {
						n := runtime.Stack(buf, true)
						if n < len(buf) {
							buf = buf[:n]
							break
						}
						buf = make([]byte, 2*len(buf))
					}
					lines := bytes.Split(buf, []byte{'\n'})
					logIt("Failed to shutdown after 30 seconds. Probably dead locked. Printing stack and killing.")
					for _, line := range lines {
						logIt(fmt.Sprintf("stack trace: %s", string(line)))
					}
					os.Exit(777)
					return
				case <-stopIt:
					t.Stop()
					return
				}
			}
		}()

		if routeChangeCallback != nil {
			routeChangeCallback.Unregister()
		}
		if uapi != nil {
			uapi.Close()
		}
		if dev != nil {
			dev.Close()
		}
		stopIt <- true
		log.Println("Shutting down")
	}()

	err = ringlogger.InitGlobalLogger("TUN")
	if err != nil {
		serviceError = ErrorRingloggerOpen
		return
	}
	defer func() {
		if x := recover(); x != nil {
			log.Printf("%v:\n%s", x, string(debug.Stack()))
			panic(x)
		}
	}()

	conf, err := conf.LoadFromPath(service.path)
	if err != nil {
		serviceError = ErrorLoadConfiguration
		return
	}

	stdLog := log.New(ringlogger.Global, fmt.Sprintf("[%s] ", conf.Name), 0)
	logger = &device.Logger{stdLog, stdLog, stdLog}

	logger.Info.Println("Starting wireguard-go version", device.WireGuardGoVersion)

	logger.Info.Println("Resolving DNS names")
	uapiConf, err := conf.ToUAPI()
	if err != nil {
		serviceError = ErrorDNSLookup
		return
	}

	logger.Info.Println("Creating Wintun device")
	wintun, err := tun.CreateTUN(conf.Name)
	if err != nil {
		serviceError = ErrorCreateWintun
		return
	}
	logger.Info.Println("Determining Wintun device name")
	realInterfaceName, err := wintun.Name()
	if err != nil {
		serviceError = ErrorDetermineWintunName
		return
	}
	conf.Name = realInterfaceName
	nativeTun := wintun.(*tun.NativeTun)

	logger.Info.Println("Enabling firewall rules")
	err = enableFirewall(conf, nativeTun)
	if err != nil {
		serviceError = ErrorFirewall
		return
	}

	logger.Info.Println("Dropping all privileges")
	err = DropAllPrivileges()
	if err != nil {
		serviceError = ErrorDropPrivileges
		return
	}

	logger.Info.Println("Creating interface instance")
	dev = device.NewDevice(wintun, logger)

	logger.Info.Println("Setting interface configuration")
	uapi, err = ipc.UAPIListen(conf.Name)
	if err != nil {
		serviceError = ErrorUAPIListen
		return
	}
	ipcErr := dev.IpcSetOperation(bufio.NewReader(strings.NewReader(uapiConf)))
	if ipcErr != nil {
		err = ipcErr
		serviceError = ErrorDeviceSetConfig
		return
	}

	logger.Info.Println("Bringing peers up")
	dev.Up()

	logger.Info.Println("Monitoring default routes")
	routeChangeCallback, err = monitorDefaultRoutes(dev, conf.Interface.Mtu == 0, nativeTun)
	if err != nil {
		serviceError = ErrorBindSocketsToDefaultRoutes
		return
	}

	logger.Info.Println("Setting device address")
	err = configureInterface(conf, nativeTun)
	if err != nil {
		serviceError = ErrorSetNetConfig
		return
	}

	logger.Info.Println("Listening for UAPI requests")
	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				continue
			}
			go dev.IpcHandle(conn)
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}
	logger.Info.Println("Startup complete")

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
