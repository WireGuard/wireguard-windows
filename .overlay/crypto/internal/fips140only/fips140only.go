/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package fips140only

import "hash"

func Enforced() bool              { return false }
func ApprovedHash(hash.Hash) bool { panic("") }
