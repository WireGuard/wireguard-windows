/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"sort"
	"strings"

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
		//TODO: use real string comparison for sorting with proper tunnel order
		return t.tunnels[i].Name < t.tunnels[j].Name
	})

	return t.SorterBase.Sort(col, order)
}

type ListView struct {
	*walk.TableView

	model *ListModel

	tunnelChangedCB  *service.TunnelChangeCallback
	tunnelsChangedCB *service.TunnelsChangeCallback
}

func NewTunnelsView(parent walk.Container) (*ListView, error) {
	var disposables walk.Disposables
	defer disposables.Treat()

	tv, err := walk.NewTableView(parent)
	if err != nil {
		return nil, err
	}
	disposables.Add(tv)

	model := new(ListModel)
	if model.tunnels, err = service.IPCClientTunnels(); err != nil {
		return nil, err
	}

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
	tunnelsView.onTunnelsChange()

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
	canvas := style.Canvas()
	if canvas == nil {
		return
	}

	tunnel := &tv.model.tunnels[style.Row()]

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
		firstTunnelName := ""
		for tunnel := range newTunnels {
			if !oldTunnels[tunnel] {
				//TODO: use proper tunnel string sorting/comparison algorithm, as the other comments indicate too.
				if len(firstTunnelName) == 0 || strings.Compare(firstTunnelName, tunnel.Name) > 0 {
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
	})
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
