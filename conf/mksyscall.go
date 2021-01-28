/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go dnsresolver_windows.go migration_windows.go storewatcher_windows.go
