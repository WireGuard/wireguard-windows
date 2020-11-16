// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"fmt"
	"net"
)

func resolveHostname(name string) (resolvedIPString string, err error) {
	ips, err := net.LookupIP(name)
	if err != nil {
		return "", err
	}
	var ip net.IP
	for _, iterip := range ips {
		if ip4 := iterip.To4(); ip4 != nil {
			ip = ip4
			break
		}
		if ip == nil {
			ip = iterip
		}
	}
	if ip == nil {
		return "", fmt.Errorf("unable to resolve IP address of endpoint %q (%v)", name, ips)
	}

	return ip.String(), nil
}
