/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"sort"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/service"
)

// TunnelModel is a struct to store the currently known tunnels to the GUI, suitable as a model for a walk.TableView.
type TunnelModel struct {
	walk.TableModelBase
	walk.SorterBase

	tunnels []service.Tunnel
}

func (t *TunnelModel) RowCount() int {
	return len(t.tunnels)
}

func (t *TunnelModel) Value(row, col int) interface{} {
	tunnel := t.tunnels[row]

	switch col {
	case 0:
		return tunnel.Name

	default:
		panic("unreachable col")
	}
}

func (t *TunnelModel) Sort(col int, order walk.SortOrder) error {
	sort.SliceStable(t.tunnels, func(i, j int) bool {
		//TODO: use real string comparison for sorting with proper tunnel order
		return t.tunnels[i].Name < t.tunnels[j].Name
	})

	return t.SorterBase.Sort(col, order)
}

type TunnelsView struct {
	*walk.TableView

	model *TunnelModel

	tunnelChangedCB  *service.TunnelChangeCallback
	tunnelsChangedCB *service.TunnelsChangeCallback
}

func NewTunnelsView(parent walk.Container) (*TunnelsView, error) {
	var disposables walk.Disposables
	defer disposables.Treat()

	tv, err := walk.NewTableView(parent)
	if err != nil {
		return nil, err
	}
	disposables.Add(tv)

	model := new(TunnelModel)
	if model.tunnels, err = service.IPCClientTunnels(); err != nil {
		return nil, err
	}

	tv.SetModel(model)
	tv.SetLastColumnStretched(true)
	tv.SetHeaderHidden(true)
	tv.SetMultiSelection(false)
	tv.Columns().Add(walk.NewTableViewColumn())

	tunnelsView := &TunnelsView{
		TableView: tv,
		model:     model,
	}

	tv.SetCellStyler(tunnelsView)

	disposables.Spare()

	tunnelsView.tunnelChangedCB = service.IPCClientRegisterTunnelChange(tunnelsView.onTunnelChange)
	tunnelsView.tunnelsChangedCB = service.IPCClientRegisterTunnelsChange(tunnelsView.onTunnelsChange)
	tunnelsView.onTunnelsChange()

	return tunnelsView, nil
}

func (tv *TunnelsView) Dispose() {
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

func (tv *TunnelsView) StyleCell(style *walk.CellStyle) {
	canvas := style.Canvas()
	if canvas == nil {
		return
	}

	tunnel := &tv.model.tunnels[style.Row()]

	b := style.Bounds()

	b.X = b.Height
	b.Width -= b.Height
	canvas.DrawText(tunnel.Name, tv.Font(), 0, b, walk.TextVCenter)

	b.X = 0
	b.Width = b.Height

	iconProvider.PaintForTunnel(tunnel, canvas, b)
}

func (tv *TunnelsView) CurrentTunnel() *service.Tunnel {
	idx := tv.CurrentIndex()
	if idx == -1 {
		return nil
	}

	return &tv.model.tunnels[idx]
}

func (tv *TunnelsView) onTunnelChange(tunnel *service.Tunnel, state service.TunnelState, err error) {
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

func (tv *TunnelsView) onTunnelsChange() {
	tunnels, err := service.IPCClientTunnels()
	if err != nil {
		return
	}
	tv.Synchronize(func() {
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
						tv.model.PublishRowsRemoved(i, i)
						break
					}
				}
			}
		}
		didAdd := false
		for tunnel := range newTunnels {
			if !oldTunnels[tunnel] {
				tv.model.tunnels = append(tv.model.tunnels, tunnel)
				didAdd = true
				//TODO: If adding a tunnel for the first time when the previously were none, select it
			}
		}
		if didAdd {
			tv.model.PublishRowsReset()
			tv.model.Sort(tv.model.SortedColumn(), tv.model.SortOrder())
		}
	})
}
