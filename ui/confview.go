/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/service"
)

const statusImageSize = 19

type widgetsLine interface {
	widgets() (walk.Widget, walk.Widget)
}

type widgetsLinesView interface {
	widgetsLines() []widgetsLine
}

type labelStatusLine struct {
	label           *walk.TextLabel
	statusComposite *walk.Composite
	statusImage     *walk.ImageView
	statusLabel     *walk.TextLabel
	imageProvider   *TunnelStatusImageProvider
}

type labelTextLine struct {
	label *walk.TextLabel
	text  *walk.LineEdit
}

type toggleActiveLine struct {
	composite     *walk.Composite
	button        *walk.PushButton
	tunnelTracker *TunnelTracker
}

type interfaceView struct {
	status       *labelStatusLine
	publicKey    *labelTextLine
	listenPort   *labelTextLine
	mtu          *labelTextLine
	addresses    *labelTextLine
	dns          *labelTextLine
	toggleActive *toggleActiveLine
	lines        []widgetsLine
}

type peerView struct {
	publicKey           *labelTextLine
	presharedKey        *labelTextLine
	allowedIPs          *labelTextLine
	endpoint            *labelTextLine
	persistentKeepalive *labelTextLine
	latestHandshake     *labelTextLine
	transfer            *labelTextLine
	lines               []widgetsLine
}

type ConfView struct {
	*walk.ScrollView
	name      *walk.GroupBox
	interfaze *interfaceView
	peers     map[conf.Key]*peerView

	tunnelChangedCB *service.TunnelChangeCallback
	tunnel          *service.Tunnel
	originalWndProc uintptr
	creatingThread  uint32
}

func (lsl *labelStatusLine) Dispose() {
	if lsl.imageProvider != nil {
		lsl.imageProvider.Dispose()
		lsl.imageProvider = nil
	}
}

func (lsl *labelStatusLine) widgets() (walk.Widget, walk.Widget) {
	return lsl.label, lsl.statusComposite
}

func (lsl *labelStatusLine) update(state service.TunnelState) {
	img, _ := lsl.imageProvider.ImageForState(state, walk.Size{statusImageSize, statusImageSize})
	lsl.statusImage.SetImage(img)

	switch state {
	case service.TunnelStarted:
		lsl.statusLabel.SetText("Active")

	case service.TunnelStarting:
		lsl.statusLabel.SetText("Activating")

	case service.TunnelStopped:
		lsl.statusLabel.SetText("Inactive")

	case service.TunnelStopping:
		lsl.statusLabel.SetText("Deactivating")
	}
}

func newLabelStatusLine(parent walk.Container) *labelStatusLine {
	lsl := new(labelStatusLine)
	parent.AddDisposable(lsl)

	lsl.label, _ = walk.NewTextLabel(parent)
	lsl.label.SetText("Status:")
	lsl.label.SetTextAlignment(walk.AlignHFarVCenter)

	lsl.statusComposite, _ = walk.NewComposite(parent)
	layout := walk.NewHBoxLayout()
	layout.SetMargins(walk.Margins{})
	lsl.statusComposite.SetLayout(layout)

	lsl.imageProvider, _ = NewTunnelStatusImageProvider()
	lsl.statusImage, _ = walk.NewImageView(lsl.statusComposite)
	lsl.statusLabel, _ = walk.NewTextLabel(lsl.statusComposite)
	lsl.statusLabel.SetTextAlignment(walk.AlignHNearVCenter)
	walk.NewVSpacerFixed(lsl.statusComposite, 26)
	walk.NewHSpacer(lsl.statusComposite)
	lsl.update(service.TunnelStopped)

	return lsl
}

func (lt *labelTextLine) widgets() (walk.Widget, walk.Widget) {
	return lt.label, lt.text
}

func (lt *labelTextLine) show(text string) {
	s, e := lt.text.TextSelection()
	lt.text.SetText(text)
	lt.label.SetVisible(true)
	lt.text.SetVisible(true)
	lt.text.SetTextSelection(s, e)
}

func (lt *labelTextLine) hide() {
	lt.text.SetText("")
	lt.label.SetVisible(false)
	lt.text.SetVisible(false)
}

func newLabelTextLine(fieldName string, parent walk.Container) *labelTextLine {
	lt := new(labelTextLine)
	lt.label, _ = walk.NewTextLabel(parent)
	lt.label.SetText(fieldName + ":")
	lt.label.SetTextAlignment(walk.AlignHFarVNear)
	lt.label.SetVisible(false)

	lt.text, _ = walk.NewLineEdit(parent)
	win.SetWindowLong(lt.text.Handle(), win.GWL_EXSTYLE, win.GetWindowLong(lt.text.Handle(), win.GWL_EXSTYLE)&^win.WS_EX_CLIENTEDGE)
	lt.text.SetReadOnly(true)
	lt.text.SetBackground(walk.NullBrush())
	lt.text.SetVisible(false)
	lt.text.FocusedChanged().Attach(func() {
		lt.text.SetTextSelection(0, 0)
	})
	return lt
}

func (tal *toggleActiveLine) widgets() (walk.Widget, walk.Widget) {
	return nil, tal.composite
}

func (tal *toggleActiveLine) update(state service.TunnelState) {
	var enabled bool
	var text string

	switch state {
	case service.TunnelStarted:
		enabled, text = true, "Deactivate"

	case service.TunnelStarting:
		enabled, text = false, "Activating..."

	case service.TunnelStopped:
		enabled, text = true, "Activate"

	case service.TunnelStopping:
		enabled, text = false, "Deactivating..."

	default:
		enabled, text = false, ""
	}

	if tt := tal.tunnelTracker; tt != nil && tt.InTransition() {
		enabled = false
	}

	tal.button.SetEnabled(enabled)
	tal.button.SetText(text)
	tal.button.SetVisible(state != service.TunnelUnknown)
}

func newToggleActiveLine(parent walk.Container) *toggleActiveLine {
	tal := new(toggleActiveLine)

	tal.composite, _ = walk.NewComposite(parent)
	layout := walk.NewHBoxLayout()
	layout.SetMargins(walk.Margins{0, 0, 0, 6})
	tal.composite.SetLayout(layout)

	tal.button, _ = walk.NewPushButton(tal.composite)
	walk.NewHSpacer(tal.composite)
	tal.update(service.TunnelStopped)

	return tal
}

func newInterfaceView(parent walk.Container) *interfaceView {
	iv := &interfaceView{
		newLabelStatusLine(parent),
		newLabelTextLine("Public key", parent),
		newLabelTextLine("Listen port", parent),
		newLabelTextLine("MTU", parent),
		newLabelTextLine("Addresses", parent),
		newLabelTextLine("DNS servers", parent),
		newToggleActiveLine(parent),
		nil,
	}
	iv.lines = []widgetsLine{
		iv.status,
		iv.publicKey,
		iv.listenPort,
		iv.mtu,
		iv.addresses,
		iv.dns,
		iv.toggleActive,
	}
	layoutInGrid(iv, parent.Layout().(*walk.GridLayout))
	return iv
}

func newPeerView(parent walk.Container) *peerView {
	pv := &peerView{
		newLabelTextLine("Public key", parent),
		newLabelTextLine("Preshared key", parent),
		newLabelTextLine("Allowed IPs", parent),
		newLabelTextLine("Endpoint", parent),
		newLabelTextLine("Persistent keepalive", parent),
		newLabelTextLine("Latest handshake", parent),
		newLabelTextLine("Transfer", parent),
		nil,
	}
	pv.lines = []widgetsLine{
		pv.publicKey,
		pv.presharedKey,
		pv.allowedIPs,
		pv.endpoint,
		pv.persistentKeepalive,
		pv.latestHandshake,
		pv.transfer,
	}
	layoutInGrid(pv, parent.Layout().(*walk.GridLayout))
	return pv
}

func layoutInGrid(view widgetsLinesView, layout *walk.GridLayout) {
	for i, l := range view.widgetsLines() {
		w1, w2 := l.widgets()

		if w1 != nil {
			layout.SetRange(w1, walk.Rectangle{0, i, 1, 1})
		}
		if w2 != nil {
			layout.SetRange(w2, walk.Rectangle{2, i, 1, 1})
		}
	}
}

func (iv *interfaceView) widgetsLines() []widgetsLine {
	return iv.lines
}

func (iv *interfaceView) apply(c *conf.Interface) {
	iv.publicKey.show(c.PrivateKey.Public().String())

	if c.ListenPort > 0 {
		iv.listenPort.show(strconv.Itoa(int(c.ListenPort)))
	} else {
		iv.listenPort.hide()
	}

	if c.Mtu > 0 {
		iv.mtu.show(strconv.Itoa(int(c.Mtu)))
	} else {
		iv.mtu.hide()
	}

	if len(c.Addresses) > 0 {
		addrStrings := make([]string, len(c.Addresses))
		for i, address := range c.Addresses {
			addrStrings[i] = address.String()
		}
		iv.addresses.show(strings.Join(addrStrings[:], ", "))
	} else {
		iv.addresses.hide()
	}

	if len(c.Dns) > 0 {
		addrStrings := make([]string, len(c.Dns))
		for i, address := range c.Dns {
			addrStrings[i] = address.String()
		}
		iv.dns.show(strings.Join(addrStrings[:], ", "))
	} else {
		iv.dns.hide()
	}
}

func (pv *peerView) widgetsLines() []widgetsLine {
	return pv.lines
}

func (pv *peerView) apply(c *conf.Peer) {
	pv.publicKey.show(c.PublicKey.String())

	if !c.PresharedKey.IsZero() {
		pv.presharedKey.show("enabled")
	} else {
		pv.presharedKey.hide()
	}

	if len(c.AllowedIPs) > 0 {
		addrStrings := make([]string, len(c.AllowedIPs))
		for i, address := range c.AllowedIPs {
			addrStrings[i] = address.String()
		}
		pv.allowedIPs.show(strings.Join(addrStrings[:], ", "))
	} else {
		pv.allowedIPs.hide()
	}

	if !c.Endpoint.IsEmpty() {
		pv.endpoint.show(c.Endpoint.String())
	} else {
		pv.endpoint.hide()
	}

	if c.PersistentKeepalive > 0 {
		pv.persistentKeepalive.show(strconv.Itoa(int(c.PersistentKeepalive)))
	} else {
		pv.persistentKeepalive.hide()
	}

	if !c.LastHandshakeTime.IsEmpty() {
		pv.latestHandshake.show(c.LastHandshakeTime.String())
	} else {
		pv.latestHandshake.hide()
	}

	if c.RxBytes > 0 || c.TxBytes > 0 {
		pv.transfer.show(fmt.Sprintf("%s received, %s sent", c.RxBytes.String(), c.TxBytes.String()))
	} else {
		pv.transfer.hide()
	}
}

func newPaddedGroupGrid(parent walk.Container) (group *walk.GroupBox, err error) {
	group, err = walk.NewGroupBox(parent)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			group.Dispose()
		}
	}()
	layout := walk.NewGridLayout()
	layout.SetMargins(walk.Margins{10, 15, 10, 5})
	err = group.SetLayout(layout)
	if err != nil {
		return nil, err
	}
	spacer, err := walk.NewSpacerWithCfg(group, &walk.SpacerCfg{walk.GrowableHorz | walk.GreedyHorz, walk.Size{10, 0}, false})
	if err != nil {
		return nil, err
	}
	layout.SetRange(spacer, walk.Rectangle{1, 0, 1, 1})
	return group, nil
}

func NewConfView(parent walk.Container) (*ConfView, error) {
	cv := new(ConfView)
	cv.ScrollView, _ = walk.NewScrollView(parent)
	cv.SetLayout(walk.NewVBoxLayout())
	cv.name, _ = newPaddedGroupGrid(cv)
	cv.interfaze = newInterfaceView(cv.name)
	cv.interfaze.toggleActive.button.Clicked().Attach(cv.onToggleActiveClicked)
	cv.peers = make(map[conf.Key]*peerView)
	cv.creatingThread = windows.GetCurrentThreadId()
	win.SetWindowLongPtr(cv.Handle(), win.GWLP_USERDATA, uintptr(unsafe.Pointer(cv)))
	cv.tunnelChangedCB = service.IPCClientRegisterTunnelChange(cv.onTunnelChanged)
	cv.SetTunnel(nil)

	if err := walk.InitWrapperWindow(cv); err != nil {
		return nil, err
	}

	return cv, nil
}

func (cv *ConfView) Dispose() {
	if cv.tunnelChangedCB != nil {
		cv.tunnelChangedCB.Unregister()
		cv.tunnelChangedCB = nil
	}

	cv.ScrollView.Dispose()
}

func (cv *ConfView) TunnelTracker() *TunnelTracker {
	return cv.interfaze.toggleActive.tunnelTracker
}

func (cv *ConfView) SetTunnelTracker(tunnelTracker *TunnelTracker) {
	cv.interfaze.toggleActive.tunnelTracker = tunnelTracker
}

func (cv *ConfView) onToggleActiveClicked() {
	cv.interfaze.toggleActive.button.SetEnabled(false)

	var title string
	var err error
	tt := cv.TunnelTracker()
	if activeTunnel := tt.ActiveTunnel(); activeTunnel != nil && activeTunnel.Name == cv.tunnel.Name {
		title = "Failed to deactivate tunnel"
		err = tt.DeactivateTunnel()
	} else {
		title = "Failed to activate tunnel"
		err = tt.ActivateTunnel(cv.tunnel)
	}
	if err != nil {
		walk.MsgBox(cv.Form(), title, err.Error(), walk.MsgBoxIconError)
		return
	}

	cv.SetTunnel(cv.tunnel)
}

func (cv *ConfView) onTunnelChanged(tunnel *service.Tunnel, state service.TunnelState, err error) {
	if cv.tunnel == nil || cv.tunnel.Name != tunnel.Name {
		return
	}

	cv.updateTunnelStatus(state)
}

func (cv *ConfView) updateTunnelStatus(state service.TunnelState) {
	cv.interfaze.status.update(state)
	cv.interfaze.toggleActive.update(state)
}

func (cv *ConfView) SetTunnel(tunnel *service.Tunnel) {
	cv.tunnel = tunnel

	var state service.TunnelState
	var config conf.Config
	if tunnel != nil {
		if state, _ = tunnel.State(); state == service.TunnelStarted {
			config, _ = tunnel.RuntimeConfig()
		}
		if config.Name == "" {
			config, _ = tunnel.StoredConfig()
		}
	}

	cv.name.SetVisible(tunnel != nil)

	hasSuspended := false
	suspend := func() {
		if !hasSuspended {
			cv.SetSuspended(true)
			hasSuspended = true
		}
	}
	defer func() {
		if hasSuspended {
			cv.SetSuspended(false)
		}
	}()
	title := "Interface: " + config.Name
	if cv.name.Title() != title {
		cv.name.SetTitle(title)
	}
	cv.interfaze.apply(&config.Interface)
	cv.updateTunnelStatus(state)
	inverse := make(map[*peerView]bool, len(cv.peers))
	for _, pv := range cv.peers {
		inverse[pv] = true
	}
	for _, peer := range config.Peers {
		if pv := cv.peers[peer.PublicKey]; pv != nil {
			pv.apply(&peer)
			inverse[pv] = false
		} else {
			suspend()
			group, _ := newPaddedGroupGrid(cv)
			group.SetTitle("Peer")
			pv := newPeerView(group)
			pv.apply(&peer)
			cv.peers[peer.PublicKey] = pv
		}
	}
	for pv, remove := range inverse {
		if !remove {
			continue
		}
		k, e := conf.NewPrivateKeyFromString(pv.publicKey.text.Text())
		if e != nil {
			continue
		}
		suspend()
		delete(cv.peers, *k)
		groupBox := pv.publicKey.label.Parent().AsContainerBase().Parent().(*walk.GroupBox)
		groupBox.Parent().Children().Remove(groupBox)
		groupBox.Dispose()
	}
}
