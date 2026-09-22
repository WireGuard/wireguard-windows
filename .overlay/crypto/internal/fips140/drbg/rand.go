/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package drbg

import (
	"crypto/internal/sysrand"
	"io"
)

func Read(b []byte) {
	sysrand.Read(b)
}

func SetTestingReader(io.Reader) {
	panic("")
}

type DefaultReader struct{}

func (DefaultReader) defaultReader() {}

func IsDefaultReader(r io.Reader) bool {
	_, ok := r.(interface{ defaultReader() })
	return ok
}

func ReadWithReader(r io.Reader, b []byte) error {
	Read(b)
	return nil
}
