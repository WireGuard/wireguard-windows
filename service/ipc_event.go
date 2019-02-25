/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import "golang.org/x/sys/windows"

//sys registerWindowMessage(name *uint16) (message uint, err error) = user32.RegisterWindowMessageW

var (
	tunnelsChangedMessage uint
	tunnelChangedMessage uint
)
func IPCRegisterEventMessages() error {
	m, err := registerWindowMessage(windows.StringToUTF16Ptr("WireGuard Manager Event - Tunnels Changed"))
	if err != nil {
		return err
	}
	tunnelsChangedMessage = m

	m, err = registerWindowMessage(windows.StringToUTF16Ptr("WireGuard Manager Event - Tunnel Changed"))
	if err != nil {
		return err
	}
	tunnelChangedMessage = m

	return nil
}
