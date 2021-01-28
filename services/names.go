/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package services

import (
	"errors"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func ServiceNameOfTunnel(tunnelName string) (string, error) {
	if !conf.TunnelNameIsValid(tunnelName) {
		return "", errors.New("Tunnel name is not valid")
	}
	return "WireGuardTunnel$" + tunnelName, nil
}

func PipePathOfTunnel(tunnelName string) (string, error) {
	if !conf.TunnelNameIsValid(tunnelName) {
		return "", errors.New("Tunnel name is not valid")
	}
	return `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\` + tunnelName, nil
}
