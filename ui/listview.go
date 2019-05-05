/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"golang.zx2c4.com/wireguard/windows/conf"
	"sort"
	"sync/atomic"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/service"
)

// ListModel is a struct to store the currently known tunnels to the GUI, suitable as a model for a walk.TableView.
type ListModel struct {
	walk.TableModelBase
	walk.SorterBase

	tunnels []service.Tunnel
}

func (t *ListModel) RowCount() int {
	return len(t.tunnels)
}

func (t *ListModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(t.tunnels) {
		return nil
	}
	tunnel := t.tunnels[row]

	switch col {
	case 0:
		return tunnel.Name

	default:
		panic("unreachable col")
	}
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

	tunnelChangedCB        *service.TunnelChangeCallback
	tunnelsChangedCB       *service.TunnelsChangeCallback
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
	tv.SetModel(model)
	tv.SetLastColumnStretched(true)
	tv.SetHeaderHidden(true)
	tv.Columns().Add(walk.NewTableViewColumn())

	tunnelsView := &ListView{
		TableView: tv,
		model:     model,
	}

	tv.SetCellStyler(tunnelsView)

	disposables.Spare()

	tunnelsView.tunnelChangedCB = service.IPCClientRegisterTunnelChange(tunnelsView.onTunnelChange)
	tunnelsView.tunnelsChangedCB = service.IPCClientRegisterTunnelsChange(tunnelsView.onTunnelsChange)

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

func (tv *ListView) StyleCell(style *walk.CellStyle) {
	row := style.Row()
	if row < 0 || row >= len(tv.model.tunnels) {
		return
	}
	tunnel := &tv.model.tunnels[row]

	canvas := style.Canvas()
	if canvas == nil {
		return
	}

	b := style.Bounds()

	b.X = b.Height
	b.Width -= b.Height
	canvas.DrawText(tunnel.Name, tv.Font(), 0, b, walk.TextVCenter|walk.TextSingleLine)

	b.X = 0
	b.Width = b.Height

	iconProvider.PaintForTunnel(tunnel, canvas, b)
}

func (tv *ListView) CurrentTunnel() *service.Tunnel {
	idx := tv.CurrentIndex()
	if idx == -1 {
		return nil
	}

	return &tv.model.tunnels[idx]
}

func (tv *ListView) onTunnelChange(tunnel *service.Tunnel, state service.TunnelState, globalState service.TunnelState, err error) {
	tv.Synchronize(func() {
		idx := -1
		for i := range tv.model.tunnels {
			if tv.model.tunnels[i].Name == tunnel.Name {
				idx = i
				break
			}
		}

		if idx != -1 {
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
	tunnels, err := service.IPCClientTunnels()
	if err != nil {
		return
	}
	doUI := func() {
		newTunnels := make(map[service.Tunnel]bool, len(tunnels))
		oldTunnels := make(map[service.Tunnel]bool, len(tv.model.tunnels))
		for _, tunnel := range tunnels {
			newTunnels[tunnel] = true
		}
		for _, tunnel := range tv.model.tunnels {
			oldTunnels[tunnel] = true
		}

		for tunnel := range oldTunnels {
			if !newTunnels[tunnel] {
				for i, t := range tv.model.tunnels {
					//TODO: this is inefficient. Use a map here instead.
					if t.Name == tunnel.Name {
						tv.model.tunnels = append(tv.model.tunnels[:i], tv.model.tunnels[i+1:]...)
						tv.model.PublishRowsRemoved(i, i) //TODO: Do we have to call that everytime or can we pass a range?
						break
					}
				}
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
	tunnels := make([]service.Tunnel, len(tv.model.tunnels))
	copy(tunnels, tv.model.tunnels)
	go func() {
		for _, tunnel := range tunnels {
			state, err := tunnel.State()
			if err != nil {
				continue
			}
			if state == service.TunnelStarting || state == service.TunnelStarted {
				tv.Synchronize(func() {
					tv.selectTunnel(tunnel.Name)
				})
				return
			}
		}
	}()
}
