/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/version"
)

type tunnelService struct {
	Path string
}

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var dev *device.Device
	var uapi net.Listener
	var watcher *interfaceWatcher
	var nativeTun *tun.NativeTun
	var config *conf.Config
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

		if logErr == nil && dev != nil && config != nil {
			logErr = runScriptCommand(config.Interface.PreDown, config.Name)
		}
		if watcher != nil {
			watcher.Destroy()
		}
		if uapi != nil {
			uapi.Close()
		}
		if dev != nil {
			dev.Close()
		}
		if logErr == nil && dev != nil && config != nil {
			_ = runScriptCommand(config.Interface.PostDown, config.Name)
		}
		stopIt <- true
		log.Println("Shutting down")
	}()

	err = ringlogger.InitGlobalLogger("TUN")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}

	config, err = conf.LoadFromPath(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}
	config.DeduplicateNetworkEntries()
	err = CopyConfigOwnerToIPCSecurityDescriptor(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}

	log.SetPrefix(fmt.Sprintf("[%s] ", config.Name))

	log.Println("Starting", version.UserAgent())

	if m, err := mgr.Connect(); err == nil {
		if lockStatus, err := m.LockStatus(); err == nil && lockStatus.IsLocked {
			/* If we don't do this, then the Wintun installation will block forever, because
			 * installing a Wintun device starts a service too. Apparently at boot time, Windows
			 * 8.1 locks the SCM for each service start, creating a deadlock if we don't announce
			 * that we're running before starting additional services.
			 */
			log.Printf("SCM locked for %v by %s, marking service as started", lockStatus.Age, lockStatus.Owner)
			changes <- svc.Status{State: svc.Running}
		}
		m.Disconnect()
	}

	log.Println("Watching network interfaces")
	watcher, err = watchInterface()
	if err != nil {
		serviceError = services.ErrorSetNetConfig
		return
	}

	log.Println("Resolving DNS names")
	uapiConf, err := config.ToUAPI()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return
	}

	log.Println("Creating Wintun interface")
	wintun, err := tun.CreateTUNWithRequestedGUID(config.Name, deterministicGUID(config), 0)
	if err != nil {
		serviceError = services.ErrorCreateWintun
		return
	}
	nativeTun = wintun.(*tun.NativeTun)
	wintunVersion, err := nativeTun.RunningVersion()
	if err != nil {
		log.Printf("Warning: unable to determine Wintun version: %v", err)
	} else {
		log.Printf("Using Wintun/%d.%d", (wintunVersion>>16)&0xffff, wintunVersion&0xffff)
	}

	err = runScriptCommand(config.Interface.PreUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	err = enableFirewall(config, nativeTun)
	if err != nil {
		serviceError = services.ErrorFirewall
		return
	}

	log.Println("Dropping privileges")
	err = elevate.DropAllPrivileges(true)
	if err != nil {
		serviceError = services.ErrorDropPrivileges
		return
	}

	log.Println("Creating interface instance")
	dev = device.NewDevice(wintun, &device.Logger{log.Printf, log.Printf})

	log.Println("Setting interface configuration")
	uapi, err = ipc.UAPIListen(config.Name)
	if err != nil {
		serviceError = services.ErrorUAPIListen
		return
	}
	err = dev.IpcSet(uapiConf)
	if err != nil {
		serviceError = services.ErrorDeviceSetConfig
		return
	}

	log.Println("Bringing peers up")
	dev.Up()

	watcher.Configure(dev, config, nativeTun)

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

	err = runScriptCommand(config.Interface.PostUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Println("Startup complete")

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected service control request #%d\n", c)
			}
		case <-dev.Wait():
			return
		case e := <-watcher.errors:
			serviceError, err = e.serviceError, e.err
			return
		}
	}
}

func Run(confPath string) error {
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		return err
	}
	serviceName, err := services.ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	return svc.Run(serviceName, &tunnelService{confPath})
}
