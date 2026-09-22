//go:build !purego

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package sha512

import "crypto/internal/fips140deps/cpu"

//go:noescape
func blockAVX2(dig *Digest, p []byte)
func block(dig *Digest, p []byte) {
	if cpu.HasSHA512AVX2() {
		blockAVX2(dig, p)
	} else {
		blockGeneric(dig, p)
	}
}
