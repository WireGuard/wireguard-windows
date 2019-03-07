/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package syntax

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/conf"
)

// #include "confview.h"
import "C"

type ConfView struct {
	walk.WidgetBase
	lastRtf string
}

func (cv *ConfView) LayoutFlags() walk.LayoutFlags {
	return walk.GrowableHorz | walk.GrowableVert | walk.GreedyHorz | walk.GreedyVert
}

func (cv *ConfView) MinSizeHint() walk.Size {
	return walk.Size{20, 12}
}

func (cv *ConfView) SizeHint() walk.Size {
	return walk.Size{200, 100}
}

func (cv *ConfView) SetConfiguration(conf *conf.Config) {
	var output strings.Builder

	if conf == nil {
		t := byte(0)
		cv.SendMessage(C.PV_NEWRTF, uintptr(unsafe.Pointer(&t)), 0)
		return
	}

	escape := func(s string) string {
		var o strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] > 127 || s[i] == '}' || s[i] == '{' || s[i] == '\\' {
				o.WriteString(fmt.Sprintf("\\'%d", s[i]))
				continue
			}
			o.WriteByte(s[i])
		}
		return o.String()
	}
	field := func(key, value string) {
		output.WriteString(fmt.Sprintf("{\\b %s:} %s\\par", escape(key), escape(value)))
	}

	output.WriteString("{\\rtf1\\ansi\\fs20")

	field("Interface", conf.Name)
	field("Public Key", conf.Interface.PrivateKey.Public().String())
	if conf.Interface.ListenPort > 0 {
		field("Listen Port", strconv.Itoa(int(conf.Interface.ListenPort)))
	}

	if conf.Interface.Mtu > 0 {
		field("MTU", strconv.Itoa(int(conf.Interface.Mtu)))
	}

	if len(conf.Interface.Addresses) > 0 {
		addrStrings := make([]string, len(conf.Interface.Addresses))
		for i, address := range conf.Interface.Addresses {
			addrStrings[i] = address.String()
		}
		field("Address", strings.Join(addrStrings[:], ", "))
	}

	if len(conf.Interface.Dns) > 0 {
		addrStrings := make([]string, len(conf.Interface.Dns))
		for i, address := range conf.Interface.Dns {
			addrStrings[i] = address.String()
		}
		field("DNS", strings.Join(addrStrings[:], ", "))
	}

	for _, peer := range conf.Peers {
		output.WriteString("\\par")
		field("Peer", peer.PublicKey.String())

		if !peer.PresharedKey.IsZero() {
			output.WriteString("{\\b Preshared Key:} {\\i enabled}\\par")
		}

		if len(peer.AllowedIPs) > 0 {
			addrStrings := make([]string, len(peer.AllowedIPs))
			for i, address := range peer.AllowedIPs {
				addrStrings[i] = address.String()
			}
			field("Allowed IPs", strings.Join(addrStrings[:], ", "))
		}

		if !peer.Endpoint.IsEmpty() {
			field("Endpoint", peer.Endpoint.String())
		}

		if peer.PersistentKeepalive > 0 {
			field("Persistent Keepalive", strconv.Itoa(int(peer.PersistentKeepalive)))
		}

		if !peer.LastHandshakeTime.IsEmpty() {
			field("Latest Handshake", peer.LastHandshakeTime.String())
		}

		if peer.RxBytes > 0 || peer.TxBytes > 0 {
			field("Transfer", fmt.Sprintf("%s received, %s sent", peer.RxBytes.String(), peer.TxBytes.String()))
		}
	}

	output.WriteString("}")

	text := output.String()
	if text == cv.lastRtf {
		return
	}
	cv.lastRtf = text

	t := C.CString(text)
	cv.SendMessage(C.PV_NEWRTF, uintptr(unsafe.Pointer(t)), 0)
	C.free(unsafe.Pointer(t))
}

func NewConfView(parent walk.Container) (*ConfView, error) {
	C.register_conf_view()
	cv := &ConfView{
		lastRtf: "",
	}
	err := walk.InitWidget(
		cv,
		parent,
		"WgConfView",
		C.CONFVIEW_STYLE,
		C.CONFVIEW_EXTSTYLE,
	)
	if err != nil {
		return nil, err
	}

	cv.GraphicsEffects().Add(walk.InteractionEffect)
	cv.GraphicsEffects().Add(walk.FocusEffect)
	return cv, nil
}
