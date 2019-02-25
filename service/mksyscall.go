/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output zsyscall_windows.go service_manager.go ipc_server.go ipc_event.go
