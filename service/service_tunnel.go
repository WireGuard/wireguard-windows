/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/winipcfg"
	"log"
	"net"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/service/tun"
)

type confElogger struct {
	elog  debug.Log
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
	path  string
	debug bool
}

func htonl(val uint32) uint32 {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, val)
	return *(*uint32)(unsafe.Pointer(&bytes[0]))
}

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var elog debug.Log
	var err error
	if service.debug {
		elog = debug.New("WireGuard")
	} else {
		//TODO: remember to clean this up in the msi uninstaller
		eventlog.InstallAsEventCreate("WireGuard", eventlog.Info|eventlog.Warning|eventlog.Error)
		elog, err = eventlog.Open("WireGuard")
		if err != nil {
			changes <- svc.Status{State: svc.StopPending}
			exitCode = ERROR_LOG_CONTAINER_OPEN_FAILED
			return
		}
	}
	log.SetOutput(elogger{elog})
	defer func() {
		if x := recover(); x != nil {
			elog.Error(1, fmt.Sprint(x))
			panic(x)
		}
	}()

	conf, err := conf.LoadFromPath(service.path)
	if err != nil {
		elog.Error(1, "Unable to load configuration file from path "+service.path+": "+err.Error())
		changes <- svc.Status{State: svc.StopPending}
		exitCode = ERROR_OPEN_FAILED
		return
	}

	logger := &Logger{
		Debug: log.New(&confElogger{elog: elog, conf: conf, level: 1}, "", 0),
		Info:  log.New(&confElogger{elog: elog, conf: conf, level: 2}, "", 0),
		Error: log.New(&confElogger{elog: elog, conf: conf, level: 3}, "", 0),
	}

	logger.Info.Println("Starting wireguard-go version", WireGuardGoVersion)
	logger.Debug.Println("Debug log enabled")

	wintun, err := tun.CreateTUN(conf.Name)
	if err == nil {
		realInterfaceName, err2 := wintun.Name()
		if err2 == nil {
			conf.Name = realInterfaceName
		}
	} else {
		logger.Error.Println("Failed to create TUN device:", err)
		changes <- svc.Status{State: svc.StopPending}
		exitCode = ERROR_ADAP_HDW_ERR
		return
	}

	device := NewDevice(wintun, logger)
	device.Up()
	logger.Info.Println("Device started")

	uapi, err := UAPIListen(conf.Name)
	if err != nil {
		logger.Error.Println("Failed to listen on uapi socket:", err)
		changes <- svc.Status{State: svc.StopPending}
		exitCode = ERROR_PIPE_LISTENING
		device.Close()
		return
	}
	errs := make(chan error)

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go ipcHandle(device, conn)
		}
	}()
	logger.Info.Println("UAPI listener started")
	uapiConf, err := conf.ToUAPI()
	if err != nil {
		logger.Error.Println("Failed to convert to UAPI serialization:", err)
		changes <- svc.Status{State: svc.StopPending}
		exitCode = ERROR_INVALID_PARAMETER
		device.Close()
		return
	}
	ipcSetOperation(device, bufio.NewReader(strings.NewReader(uapiConf)))

	//TODO: This needs more error checking and to be done in a notifier whenever the default route changes.
	defaultV4, err := winipcfg.DefaultInterface(winipcfg.AF_INET)
	if err == nil {
		sysconn, _ := device.net.bind.(*NativeBind).ipv4.SyscallConn()
		sysconn.Control(func(fd uintptr) {
			err = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31 /* IP_UNICAST_IF */, int(htonl(defaultV4.Index)))
			if err != nil {
				logger.Error.Println("Failed to set IPv4 default interface on socket:", err)
			}
		})
	} else {
		logger.Error.Println("Unable to determine default IPv4 interface:", err)
	}
	defaultV6, err := winipcfg.DefaultInterface(winipcfg.AF_INET6)
	if err == nil {
		sysconn, _ := device.net.bind.(*NativeBind).ipv6.SyscallConn()
		sysconn.Control(func(fd uintptr) {
			err = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31 /* IPV6_UNICAST_IF */, int(defaultV6.Ipv6IfIndex))
			if err != nil {
				logger.Error.Println("Failed to set IPv6 default interface on socket:", err)
			}
		})
	} else {
		logger.Error.Println("Unable to determine default IPv6 interface:", err)
	}

	guid := wintun.(*tun.NativeTun).GUID()
	iface, err := winipcfg.InterfaceFromGUID(&guid)
	if err != nil {
		logger.Error.Println("Unable to find Wintun device:", err)
		changes <- svc.Status{State: svc.StopPending}
		exitCode = ERROR_NETWORK_BUSY
		device.Close()
		return
	}

	routeCount := len(conf.Interface.Addresses)
	for _, peer := range conf.Peers {
		routeCount += len(peer.AllowedIPs)
	}
	routes := make([]winipcfg.RouteData, routeCount)
	routeCount = 0
	var firstGateway *net.IP
	addresses := make([]*net.IPNet, len(conf.Interface.Addresses))
	for i, addr := range conf.Interface.Addresses {
		ipnet := addr.IPNet()
		addresses[i] = &ipnet
		gateway := ipnet.IP.Mask(ipnet.Mask)
		if firstGateway == nil {
			firstGateway = &gateway
		}
		routes[routeCount] = winipcfg.RouteData{
			Destination: net.IPNet{
				IP:   gateway,
				Mask: ipnet.Mask,
			},
			NextHop: gateway,
			Metric:  1,
		}
		routeCount++
	}

	for _, peer := range conf.Peers {
		for _, allowedip := range peer.AllowedIPs {
			routes[routeCount] = winipcfg.RouteData{
				Destination: allowedip.IPNet(),
				NextHop:     *firstGateway,
				Metric:      1,
			}
			routeCount++
		}
	}

	err = iface.SetAddresses(addresses)
	if err == nil {
		err = iface.FlushRoutes()
		if err == nil {
			for _, route := range routes {
				err = iface.AddRoute(&route, true)

				//TODO: Ignoring duplicate errors like this maybe isn't very reasonable.
				// instead we should make sure we're not adding duplicates ourselves when
				// inserting the gateway routes.
				if syserr, ok := err.(*os.SyscallError); ok {
					if syserr.Err == windows.Errno(ERROR_OBJECT_ALREADY_EXISTS) {
						err = nil
					}
				}

				if err != nil {
					break
				}
			}
		}
	}
	if err == nil {
		err = iface.SetDNS(conf.Interface.Dns)
	}
	if err != nil {
		logger.Error.Println("Unable to set interface addresses, routes, or DNSes:", err)
		changes <- svc.Status{State: svc.StopPending}
		exitCode = ERROR_NETWORK_BUSY
		device.Close()
		return
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop:
				break loop
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				logger.Error.Printf("Unexpected service control request #%d", c)
			}
		case <-errs:
			break loop
		case <-device.Wait():
			break loop
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	logger.Info.Println("Shutting down")
	uapi.Close()
	device.Close()
	return
}
