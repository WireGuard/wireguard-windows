// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

func platformEnvelope(bytes []byte, name string) ([]byte, error) {
	return bytes, nil
}

func platformUnenvelope(bytes []byte, name string) ([]byte, error) {
	return bytes, nil
}
