/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/ui"
	"log"
	"runtime"
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

func main(){
	mw, _ := walk.NewMainWindowWithName("Test ConfView")
	mw.SetSize(walk.Size{600, 800})
	mw.SetLayout(walk.NewVBoxLayout())
	cv, err := ui.NewConfView(mw)
	if err != nil {
		log.Fatal(err)
	}
	config, _ := conf.FromWgQuick(demoConfig, "demo")
	peer := config.Peers[0]
	config.Peers = make([]conf.Peer, 0)

	pb1, _ := walk.NewPushButton(mw)
	pb1.SetText("Add and increment")
	pb1.Clicked().Attach(func() {
		config.Interface.ListenPort++
		config.Peers = append(config.Peers, peer)
		k,_ :=  conf.NewPrivateKey()
		config.Peers[len(config.Peers) - 1].PublicKey = *k
		cv.SetConfiguration(config)
	})
	pb2, _ := walk.NewPushButton(mw)
	pb2.SetText("Remove first peer")
	pb2.Clicked().Attach(func() {
		if len(config.Peers) < 1 {
			return
		}
		config.Interface.ListenPort--
		config.Peers = config.Peers[1:]
		cv.SetConfiguration(config)
	})
	pb3, _ := walk.NewPushButton(mw)
	pb3.SetText("Toggle MTU")
	pb3.Clicked().Attach(func() {
		config.Interface.Mtu = (config.Interface.Mtu + 1) % 2
		cv.SetConfiguration(config)
	})
	mw.SetVisible(true)
	mw.Show()
	mw.Activate()
	mw.Run()
	runtime.KeepAlive(cv)
}