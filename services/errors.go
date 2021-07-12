/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package services

import (
	"fmt"

	"golang.org/x/sys/windows"
)

type Error uint32

const (
	ErrorSuccess Error = iota
	ErrorRingloggerOpen
	ErrorLoadConfiguration
	ErrorCreateNetworkAdapter
	ErrorUAPIListen
	ErrorDNSLookup
	ErrorFirewall
	ErrorDeviceSetConfig
	ErrorDeviceBringUp
	ErrorBindSocketsToDefaultRoutes
	ErrorMonitorMTUChanges
	ErrorSetNetConfig
	ErrorDetermineExecutablePath
	ErrorTrackTunnels
	ErrorEnumerateSessions
	ErrorDropPrivileges
	ErrorRunScript
	ErrorWin32
)

func (e Error) Error() string {
	switch e {
	case ErrorSuccess:
		return "No error"
	case ErrorRingloggerOpen:
		return "Unable to open log file"
	case ErrorDetermineExecutablePath:
		return "Unable to determine path of running executable"
	case ErrorLoadConfiguration:
		return "Unable to load configuration from path"
	case ErrorCreateNetworkAdapter:
		return "Unable to create network adapter"
	case ErrorUAPIListen:
		return "Unable to listen on named pipe"
	case ErrorDNSLookup:
		return "Unable to resolve one or more DNS hostname endpoints"
	case ErrorFirewall:
		return "Unable to enable firewall rules"
	case ErrorDeviceSetConfig:
		return "Unable to set device configuration"
	case ErrorDeviceBringUp:
		return "Unable to bring up adapter"
	case ErrorBindSocketsToDefaultRoutes:
		return "Unable to bind sockets to default route"
	case ErrorMonitorMTUChanges:
		return "Unable to monitor default route MTU for changes"
	case ErrorSetNetConfig:
		return "Unable to set interface addresses, routes, dns, and/or interface settings"
	case ErrorTrackTunnels:
		return "Unable to track existing tunnels"
	case ErrorEnumerateSessions:
		return "Unable to enumerate current sessions"
	case ErrorDropPrivileges:
		return "Unable to drop privileges"
	case ErrorRunScript:
		return "An error occurred while running a configuration script command"
	case ErrorWin32:
		return "An internal Windows error has occurred"
	default:
		return "An unknown error has occurred"
	}
}

func DetermineErrorCode(err error, serviceError Error) (bool, uint32) {
	if syserr, ok := err.(windows.Errno); ok {
		return false, uint32(syserr)
	} else if serviceError != ErrorSuccess {
		return true, uint32(serviceError)
	} else {
		return false, windows.NO_ERROR
	}
}

func CombineErrors(err error, serviceError Error) error {
	if serviceError != ErrorSuccess {
		if err != nil {
			return fmt.Errorf("%v: %w", serviceError, err)
		}
		return serviceError
	}
	return err
}
