/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"golang.zx2c4.com/wireguard/windows/conf/dpapi"
)

func platformEnvelope(bytes []byte, name string) ([]byte, error) {
	return dpapi.Encrypt(bytes, name)
}

func platformUnenvelope(bytes []byte, name string) ([]byte, error) {
	return dpapi.Decrypt(bytes, name)
}
