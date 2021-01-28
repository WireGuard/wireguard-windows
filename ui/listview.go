/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"sort"
	"sync/atomic"

	"github.com/lxn/win"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/manager"

	"github.com/lxn/walk"
)

// ListModel is a struct to store the currently known tunnels to the GUI, suitable as a model for a walk.TableView.
type ListModel struct {
	walk.TableModelBase
	walk.SorterBase

	tunnels           []manager.Tunnel
	lastObservedState map[manager.Tunnel]manager.TunnelState
}

var cachedListViewIconsForWidthAndState = make(map[widthAndState]*walk.Bitmap)

func (t *ListModel) RowCount() int {
	return len(t.tunnels)
}

func (t *ListModel) Value(row, col int) interface{} {
	if col != 0 || row < 0 || row >= len(t.tunnels) {
		return ""
	}
	return t.tunnels[row].Name
}

func (t *ListModel) Sort(col int, order walk.SortOrder) error {
	sort.SliceStable(t.tunnels, func(i, j int) bool {
		return conf.TunnelNameIsLess(t.tunnels[i].Name, t.tunnels[j].Name)
	})

	return t.SorterBase.Sort(col, order)
}

type ListView struct {
	*walk.TableView

	model *ListModel

	tunnelChangedCB        *manager.TunnelChangeCallback
	tunnelsChangedCB       *manager.TunnelsChangeCallback
	tunnelsUpdateSuspended int32
}

func NewListView(parent walk.Container) (*ListView, error) {
	var disposables walk.Disposables
	defer disposables.Treat()

	tv, err := walk.NewTableView(parent)
	if err != nil {
		return nil, err
	}
	disposables.Add(tv)

	tv.SetDoubleBuffering(true)

	model := new(ListModel)
	model.lastObservedState = make(map[manager.Tunnel]manager.TunnelState)
	tv.SetModel(model)
	tv.SetLastColumnStretched(true)
	tv.SetHeaderHidden(true)
	tv.SetIgnoreNowhere(true)
	tv.SetScrollbarOrientation(walk.Vertical)
	tv.Columns().Add(walk.NewTableViewColumn())

	tunnelsView := &ListView{
		TableView: tv,
		model:     model,
	}
	tv.SetCellStyler(tunnelsView)

	disposables.Spare()

	tunnelsView.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(tunnelsView.onTunnelChange)
	tunnelsView.tunnelsChangedCB = manager.IPCClientRegisterTunnelsChange(tunnelsView.onTunnelsChange)

	return tunnelsView, nil
}

func (tv *ListView) Dispose() {
	if tv.tunnelChangedCB != nil {
		tv.tunnelChangedCB.Unregister()
		tv.tunnelChangedCB = nil
	}
	if tv.tunnelsChangedCB != nil {
		tv.tunnelsChangedCB.Unregister()
		tv.tunnelsChangedCB = nil
	}
	tv.TableView.Dispose()
}

func (tv *ListView) CurrentTunnel() *manager.Tunnel {
	idx := tv.CurrentIndex()
	if idx == -1 {
		return nil
	}

	return &tv.model.tunnels[idx]
}

var dummyBitmap *walk.Bitmap

func (tv *ListView) StyleCell(style *walk.CellStyle) {
	row := style.Row()
	if row < 0 || row >= len(tv.model.tunnels) {
		return
	}
	tunnel := &tv.model.tunnels[row]

	var state manager.TunnelState
	var ok bool
	state, ok = tv.model.lastObservedState[tv.model.tunnels[row]]
	if !ok {
		var err error
		state, err = tunnel.State()
		if err != nil {
			return
		}
		tv.model.lastObservedState[tv.model.tunnels[row]] = state
	}

	icon, err := iconForState(state, 14)
	if err != nil {
		return
	}
	margin := tv.IntFrom96DPI(1)
	bitmapWidth := tv.IntFrom96DPI(16)

	if win.IsAppThemed() {
		cacheKey := widthAndState{bitmapWidth, state}
		if cacheValue, ok := cachedListViewIconsForWidthAndState[cacheKey]; ok {
			style.Image = cacheValue
			return
		}
		bitmap, err := walk.NewBitmapWithTransparentPixelsForDPI(walk.Size{bitmapWidth, bitmapWidth}, tv.DPI())
		if err != nil {
			return
		}
		canvas, err := walk.NewCanvasFromImage(bitmap)
		if err != nil {
			return
		}
		bounds := walk.Rectangle{X: margin, Y: margin, Height: bitmapWidth - 2*margin, Width: bitmapWidth - 2*margin}
		err = canvas.DrawImageStretchedPixels(icon, bounds)
		canvas.Dispose()
		if err != nil {
			return
		}
		cachedListViewIconsForWidthAndState[cacheKey] = bitmap
		style.Image = bitmap
	} else {
		if dummyBitmap == nil {
			dummyBitmap, _ = walk.NewBitmapForDPI(tv.SizeFrom96DPI(walk.Size{}), 96)
		}
		style.Image = dummyBitmap
		canvas := style.Canvas()
		if canvas == nil {
			return
		}
		bounds := style.BoundsPixels()
		bounds.Width = bitmapWidth - 2*margin
		bounds.X = (bounds.Height - bounds.Width) / 2
		bounds.Height = bounds.Width
		bounds.Y += bounds.X
		canvas.DrawImageStretchedPixels(icon, bounds)
	}
}

func (tv *ListView) onTunnelChange(tunnel *manager.Tunnel, state manager.TunnelState, globalState manager.TunnelState, err error) {
	tv.Synchronize(func() {
		idx := -1
		for i := range tv.model.tunnels {
			if tv.model.tunnels[i].Name == tunnel.Name {
				idx = i
				break
			}
		}

		if idx != -1 {
			tv.model.lastObservedState[tv.model.tunnels[idx]] = state
			tv.model.PublishRowChanged(idx)
			return
		}
	})
}

func (tv *ListView) onTunnelsChange() {
	if atomic.LoadInt32(&tv.tunnelsUpdateSuspended) == 0 {
		tv.Load(true)
	}
}

func (tv *ListView) SetSuspendTunnelsUpdate(suspend bool) {
	if suspend {
		atomic.AddInt32(&tv.tunnelsUpdateSuspended, 1)
	} else {
		atomic.AddInt32(&tv.tunnelsUpdateSuspended, -1)
	}
	tv.Load(true)
}

func (tv *ListView) Load(asyncUI bool) {
	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		return
	}
	doUI := func() {
		newTunnels := make(map[manager.Tunnel]bool, len(tunnels))
		oldTunnels := make(map[manager.Tunnel]bool, len(tv.model.tunnels))
		for _, tunnel := range tunnels {
			newTunnels[tunnel] = true
		}
		for i := len(tv.model.tunnels); i > 0; {
			i--
			tunnel := tv.model.tunnels[i]
			oldTunnels[tunnel] = true
			if !newTunnels[tunnel] {
				tv.model.tunnels = append(tv.model.tunnels[:i], tv.model.tunnels[i+1:]...)
				tv.model.PublishRowsRemoved(i, i) // TODO: Do we have to call that everytime or can we pass a range?
				delete(tv.model.lastObservedState, tunnel)
			}
		}
		didAdd := false
		firstTunnelName := ""
		for tunnel := range newTunnels {
			if !oldTunnels[tunnel] {
				if len(firstTunnelName) == 0 || !conf.TunnelNameIsLess(firstTunnelName, tunnel.Name) {
					firstTunnelName = tunnel.Name
				}
				tv.model.tunnels = append(tv.model.tunnels, tunnel)
				didAdd = true
			}
		}
		if didAdd {
			tv.model.PublishRowsReset()
			tv.model.Sort(tv.model.SortedColumn(), tv.model.SortOrder())
			if len(tv.SelectedIndexes()) == 0 {
				tv.selectTunnel(firstTunnelName)
			}
		}
	}
	if asyncUI {
		tv.Synchronize(doUI)
	} else {
		doUI()
	}
}

func (tv *ListView) selectTunnel(tunnelName string) {
	for i, tunnel := range tv.model.tunnels {
		if tunnel.Name == tunnelName {
			tv.SetCurrentIndex(i)
			break
		}
	}
}

func (tv *ListView) SelectFirstActiveTunnel() {
	tunnels := make([]manager.Tunnel, len(tv.model.tunnels))
	copy(tunnels, tv.model.tunnels)
	go func() {
		for _, tunnel := range tunnels {
			state, err := tunnel.State()
			if err != nil {
				continue
			}
			if state == manager.TunnelStarting || state == manager.TunnelStarted {
				tv.Synchronize(func() {
					tv.selectTunnel(tunnel.Name)
				})
				return
			}
		}
	}()
}
