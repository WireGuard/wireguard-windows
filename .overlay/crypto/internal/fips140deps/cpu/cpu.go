/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package cpu

import "internal/cpu"

func HasSHA512AVX2() bool {
	return cpu.X86.HasAVX && cpu.X86.HasAVX2 && cpu.X86.HasBMI2
}
func HasSHA512ARM64() bool {
	return cpu.ARM64.HasSHA512
}
