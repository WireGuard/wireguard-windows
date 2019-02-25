/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/service"
	"golang.zx2c4.com/wireguard/windows/ui/internal/walk"
	"golang.zx2c4.com/wireguard/windows/ui/syntax"
	"os"
)

const demoConfig = `[Interface]
PrivateKey = 6KpcbNFK4tKBciKBT2Rj6Z/sHBqxdV+p+nuNA5AlWGI=
Address = 192.168.4.84/24
DNS = 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = JRI8Xc0zKP9kXk8qP84NdUQA04h6DLfFbwJn4g+/PFs=
Endpoint = demo.wireguard.com:12912
AllowedIPs = 0.0.0.0/0
`

func RunUI() {
	icon, _ := walk.NewIconFromResourceId(8)

	mw, _ := walk.NewMainWindowWithName("WireGuard")
	tray, _ := walk.NewNotifyIcon(mw)
	defer tray.Dispose()
	tray.SetIcon(icon)
	tray.SetToolTip("WireGuard: Disconnected")
	tray.SetVisible(true)

	mw.SetSize(walk.Size{900, 800})
	mw.SetLayout(walk.NewVBoxLayout())
	mw.SetIcon(icon)
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		*canceled = true
		mw.Hide()
	})

	tl, _ := walk.NewTextLabel(mw)
	tl.SetText("Public key: (unknown)")

	se, _ := syntax.NewSyntaxEdit(mw)
	lastPrivate := ""
	se.PrivateKeyChanged().Attach(func(privateKey string) {
		if privateKey == lastPrivate {
			return
		}
		lastPrivate = privateKey
		key := func() string {
			if privateKey == "" {
				return ""
			}
			decoded, err := base64.StdEncoding.DecodeString(privateKey)
			if err != nil {
				return ""
			}
			if len(decoded) != 32 {
				return ""
			}
			var p [32]byte
			var s [32]byte
			copy(s[:], decoded[:32])
			curve25519.ScalarBaseMult(&p, &s)
			return base64.StdEncoding.EncodeToString(p[:])
		}()
		if key != "" {
			tl.SetText("Public key: " + key)
		} else {
			tl.SetText("Public key: (unknown)")
		}
	})
	se.SetText(demoConfig)

	pb, _ := walk.NewPushButton(mw)
	pb.SetText("Start")
	var runningTunnel *service.Tunnel
	pb.Clicked().Attach(func() {
		if runningTunnel != nil {
			_, err := runningTunnel.Stop()
			if err != nil {
				walk.MsgBox(mw, "Unable to stop tunnel", err.Error(), walk.MsgBoxIconError)
				return
			}
			runningTunnel = nil
			pb.SetText("Start")
			tray.SetToolTip("WireGuard: Disconnected")
			return
		}
		c, err := conf.FromWgQuick(se.Text(), "test")
		if err != nil {
			walk.MsgBox(mw, "Invalid configuration", err.Error(), walk.MsgBoxIconError)
			return
		}
		tunnel, err := service.IPCClientNewTunnel(c)
		if err != nil {
			walk.MsgBox(mw, "Unable to create tunnel", err.Error(), walk.MsgBoxIconError)
			return
		}
		_, err = tunnel.Start()
		if err != nil {
			walk.MsgBox(mw, "Unable to start tunnel", err.Error(), walk.MsgBoxIconError)
			return
		}
		runningTunnel = &tunnel
		pb.SetText("Stop")
		tray.SetToolTip("WireGuard: Connected")
	})

	quitAction := walk.NewAction()
	quitAction.SetText("Exit")
	quitAction.Triggered().Attach(func() {
		tray.Dispose()
		_, err := service.IPCClientQuit(true)
		if err != nil {
			walk.MsgBox(nil, "Error Exiting WireGuard", fmt.Sprintf("Unable to exit service due to: %s. You may want to stop WireGuard from the service manager.", err), walk.MsgBoxIconError)
			os.Exit(1)
		}
	})
	tray.ContextMenu().Actions().Add(quitAction)
	tray.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			mw.Show()
		}
	})

	err := service.IPCClientRegisterAsNotificationThread()
	if err != nil {
		walk.MsgBox(mw, "Unable to register for notifications", err.Error(), walk.MsgBoxIconError)
		os.Exit(1)
	}
	mw.Run()
}
