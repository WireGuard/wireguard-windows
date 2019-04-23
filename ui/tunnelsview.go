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
		return t.tunnels[i].Name < t.tunnels[j].Name
	})

	return t.SorterBase.Sort(col, order)
}

type TunnelsView struct {
	*walk.TableView

	model         *TunnelModel
	imageProvider *TunnelStatusImageProvider
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

	if tunnelsView.imageProvider, err = NewTunnelStatusImageProvider(); err != nil {
		return nil, err
	}
	tunnelsView.AddDisposable(tunnelsView.imageProvider)

	tv.SetCellStyler(tunnelsView)

	disposables.Spare()

	return tunnelsView, nil
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

	tv.imageProvider.PaintForTunnel(tunnel, canvas, b)
}

func (tv *TunnelsView) CurrentTunnel() *service.Tunnel {
	idx := tv.CurrentIndex()
	if idx == -1 {
		return nil
	}

	return &tv.model.tunnels[idx]
}

func (tv *TunnelsView) SetTunnelState(tunnel *service.Tunnel, state service.TunnelState) {
	idx := -1
	for i, _ := range tv.model.tunnels {
		if tv.model.tunnels[i].Name == tunnel.Name {
			idx = i
			break
		}
	}

	if idx != -1 {
		tv.model.PublishRowChanged(idx)
		return
	}
}
