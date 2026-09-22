/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package rand

import (
	"crypto/internal/sysrand"
	"io"
)

func Read(b []byte) (n int, err error) {
	sysrand.Read(b) // Should panic on failure or short read
	return len(b), nil
}

type reader struct{}

func (r reader) Read(b []byte) (n int, err error) {
	return Read(b)
}

var Reader io.Reader = reader{}
