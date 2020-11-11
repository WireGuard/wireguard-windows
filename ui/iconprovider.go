/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

type widthAndState struct {
	width int
	state manager.TunnelState
}

type widthAndDllIdx struct {
	width int
	idx   int32
	dll   string
}

var cachedOverlayIconsForWidthAndState = make(map[widthAndState]walk.Image)

func iconWithOverlayForState(state manager.TunnelState, size int) (icon walk.Image, err error) {
	icon = cachedOverlayIconsForWidthAndState[widthAndState{size, state}]
	if icon != nil {
		return
	}

	wireguardIcon, err := loadLogoIcon(size)
	if err != nil {
		return
	}

	if state == manager.TunnelStopped {
		return wireguardIcon, err // TODO: if we find something prettier than the gray dot, then remove this clause
	}

	iconSize := wireguardIcon.Size()
	w := int(float64(iconSize.Width) * 0.65)
	h := int(float64(iconSize.Height) * 0.65)
	overlayBounds := walk.Rectangle{iconSize.Width - w, iconSize.Height - h, w, h}
	overlayIcon, err := iconForState(state, overlayBounds.Width)
	if err != nil {
		return
	}

	icon = walk.NewPaintFuncImage(walk.Size{size, size}, func(canvas *walk.Canvas, bounds walk.Rectangle) error {
		if err := canvas.DrawImageStretched(wireguardIcon, bounds); err != nil {
			return err
		}
		if err := canvas.DrawImageStretched(overlayIcon, overlayBounds); err != nil {
			return err
		}
		return nil
	})

	cachedOverlayIconsForWidthAndState[widthAndState{size, state}] = icon

	return
}

var cachedIconsForWidthAndState = make(map[widthAndState]*walk.Icon)

func iconForState(state manager.TunnelState, size int) (icon *walk.Icon, err error) {
	icon = cachedIconsForWidthAndState[widthAndState{size, state}]
	if icon != nil {
		return
	}
	switch state {
	case manager.TunnelStarted:
		icon, err = loadSystemIcon("imageres", -106, size)
	case manager.TunnelStopped:
		icon, err = walk.NewIconFromResourceIdWithSize(8, walk.Size{size, size}) // TODO: replace with real icon from imageres/shell32
	default:
		icon, err = loadSystemIcon("shell32", -16739, size) // TODO: this doesn't look that great overlayed on the app icon
	}
	if err == nil {
		cachedIconsForWidthAndState[widthAndState{size, state}] = icon
	}
	return
}

func textForState(state manager.TunnelState, withEllipsis bool) (text string) {
	switch state {
	case manager.TunnelStarted:
		text = l18n.Sprintf("Active")
	case manager.TunnelStarting:
		text = l18n.Sprintf("Activating")
	case manager.TunnelStopped:
		text = l18n.Sprintf("Inactive")
	case manager.TunnelStopping:
		text = l18n.Sprintf("Deactivating")
	case manager.TunnelUnknown:
		text = l18n.Sprintf("Unknown state")
	}
	if withEllipsis {
		switch state {
		case manager.TunnelStarting, manager.TunnelStopping:
			text += "…"
		}
	}
	return
}

var cachedSystemIconsForWidthAndDllIdx = make(map[widthAndDllIdx]*walk.Icon)

func loadSystemIcon(dll string, index int32, size int) (icon *walk.Icon, err error) {
	icon = cachedSystemIconsForWidthAndDllIdx[widthAndDllIdx{size, index, dll}]
	if icon != nil {
		return
	}
	icon, err = walk.NewIconFromSysDLLWithSize(dll, int(index), size)
	if err == nil {
		cachedSystemIconsForWidthAndDllIdx[widthAndDllIdx{size, index, dll}] = icon
	}
	return
}

var cachedLogoIconsForWidth = make(map[int]*walk.Icon)

func loadLogoIcon(size int) (icon *walk.Icon, err error) {
	icon = cachedLogoIconsForWidth[size]
	if icon != nil {
		return
	}
	icon, err = walk.NewIconFromResourceIdWithSize(7, walk.Size{size, size})
	if err == nil {
		cachedLogoIconsForWidth[size] = icon
	}
	return
}
