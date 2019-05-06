/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
)

type Error uint32

const (
	ErrorSuccess Error = iota
	ErrorRingloggerOpen
	ErrorLoadConfiguration
	ErrorCreateWintun
	ErrorDetermineWintunName
	ErrorUAPIListen
	ErrorDNSLookup
	ErrorFirewall
	ErrorDeviceSetConfig
	ErrorBindSocketsToDefaultRoutes
	ErrorSetNetConfig
	ErrorDetermineExecutablePath
	ErrorCreateSecurityDescriptor
	ErrorOpenNULFile
	ErrorTrackTunnels
	ErrorEnumerateSessions
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
	case ErrorCreateWintun:
		return "Unable to create Wintun device"
	case ErrorDetermineWintunName:
		return "Unable to determine Wintun name"
	case ErrorUAPIListen:
		return "Unable to listen on named pipe"
	case ErrorDNSLookup:
		return "Unable to resolve one or more DNS hostname endpoints"
	case ErrorFirewall:
		return "Unable to enable firewall rules"
	case ErrorDeviceSetConfig:
		return "Unable to set device configuration"
	case ErrorBindSocketsToDefaultRoutes:
		return "Unable to bind sockets to default route"
	case ErrorSetNetConfig:
		return "Unable to set interface addresses, routes, dns, and/or adapter settings"
	case ErrorCreateSecurityDescriptor:
		return "Unable to determine security descriptor"
	case ErrorOpenNULFile:
		return "Unable to open NUL file"
	case ErrorTrackTunnels:
		return "Unable to track existing tunnels"
	case ErrorEnumerateSessions:
		return "Unable to enumerate current sessions"
	case ErrorWin32:
		return "An internal Windows error has occurred"
	default:
		return "An unknown error has occurred"
	}
}

func determineErrorCode(err error, serviceError Error) (bool, uint32) {
	if syserr, ok := err.(syscall.Errno); ok {
		return false, uint32(syserr)
	} else if serviceError != ErrorSuccess {
		return true, uint32(serviceError)
	} else {
		return false, windows.NO_ERROR
	}
}

func combineErrors(err error, serviceError Error) error {
	if serviceError != ErrorSuccess {
		if err != nil {
			return fmt.Errorf("%v: %v", serviceError, err)
		} else {
			return serviceError
		}
	}
	return err
}

const (
	serviceDOES_NOT_EXIST    uint32 = 0x00000424
	serviceMARKED_FOR_DELETE uint32 = 0x00000430
	serviceNEVER_STARTED     uint32 = 0x00000435
)
