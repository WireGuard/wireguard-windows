/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package tunnel

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
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"golang.zx2c4.com/wireguard/windows/version"
)

type Service struct {
	Path string
}

func (service *Service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var dev *device.Device
	var uapi net.Listener
	var routeChangeCallback *winipcfg.RouteChangeCallback
	var nativeTun *tun.NativeTun
	var err error
	serviceError := services.ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = services.DetermineErrorCode(err, serviceError)
		logErr := services.CombineErrors(err, serviceError)
		if logErr != nil {
			log.Println(logErr)
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
					log.Println("Failed to shutdown after 30 seconds. Probably dead locked. Printing stack and killing.")
					for _, line := range lines {
						if len(bytes.TrimSpace(line)) > 0 {
							log.Println(string(line))
						}
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
		if nativeTun != nil {
			unconfigureInterface(nativeTun)
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
		serviceError = services.ErrorRingloggerOpen
		return
	}
	defer func() {
		if x := recover(); x != nil {
			for _, line := range append([]string{fmt.Sprint(x)}, strings.Split(string(debug.Stack()), "\n")...) {
				if len(strings.TrimSpace(line)) > 0 {
					log.Println(line)
				}
			}
			panic(x)
		}
	}()

	conf, err := conf.LoadFromPath(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}

	logPrefix := fmt.Sprintf("[%s] ", conf.Name)
	log.SetPrefix(logPrefix)

	log.Println("Starting", version.UserAgent())

	log.Println("Resolving DNS names")
	uapiConf, err := conf.ToUAPI()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return
	}

	log.Println("Creating Wintun device")
	wintun, err := tun.CreateTUN(conf.Name)
	if err != nil {
		serviceError = services.ErrorCreateWintun
		return
	}
	log.Println("Determining Wintun device name")
	realInterfaceName, err := wintun.Name()
	if err != nil {
		serviceError = services.ErrorDetermineWintunName
		return
	}
	conf.Name = realInterfaceName
	nativeTun = wintun.(*tun.NativeTun)

	log.Println("Enabling firewall rules")
	err = enableFirewall(conf, nativeTun)
	if err != nil {
		serviceError = services.ErrorFirewall
		return
	}

	log.Println("Dropping all privileges")
	err = services.DropAllPrivileges()
	if err != nil {
		serviceError = services.ErrorDropPrivileges
		return
	}

	log.Println("Creating interface instance")
	logOutput := log.New(ringlogger.Global, logPrefix, 0)
	logger := &device.Logger{logOutput, logOutput, logOutput}
	dev = device.NewDevice(wintun, logger)

	log.Println("Setting interface configuration")
	uapi, err = ipc.UAPIListen(conf.Name)
	if err != nil {
		serviceError = services.ErrorUAPIListen
		return
	}
	ipcErr := dev.IpcSetOperation(bufio.NewReader(strings.NewReader(uapiConf)))
	if ipcErr != nil {
		err = ipcErr
		serviceError = services.ErrorDeviceSetConfig
		return
	}

	log.Println("Bringing peers up")
	dev.Up()

	log.Println("Monitoring default routes")
	routeChangeCallback, err = monitorDefaultRoutes(dev, conf.Interface.MTU == 0, nativeTun)
	if err != nil {
		serviceError = services.ErrorBindSocketsToDefaultRoutes
		return
	}

	log.Println("Setting device address")
	err = configureInterface(conf, nativeTun)
	if err != nil {
		serviceError = services.ErrorSetNetConfig
		return
	}

	log.Println("Listening for UAPI requests")
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
	log.Println("Startup complete")

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop:
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected service control request #%d\n", c)
			}
		case <-dev.Wait():
			return
		}
	}
}
