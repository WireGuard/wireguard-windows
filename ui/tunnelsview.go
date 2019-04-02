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
		a, b := t.tunnels[i], t.tunnels[j]

		c := func(res bool) bool {
			if order == walk.SortAscending {
				return res
			}
			return !res
		}

		// don't match col, always sort by name
		return c(a.Name < b.Name)
	})

	return t.SorterBase.Sort(col, order)
}

type TunnelsView struct {
	*walk.TableView

	model         *TunnelModel
	stoppedBrush  *walk.SolidColorBrush
	startingBrush *walk.SolidColorBrush
	startedBrush  *walk.SolidColorBrush
	statusPen     *walk.CosmeticPen
}

func NewTunnelsView(parent walk.Container) (*TunnelsView, error) {
	tv, err := walk.NewTableView(parent)
	if err != nil {
		return nil, err
	}

	model := &TunnelModel{}

	tv.SetModel(model)
	tv.SetLastColumnStretched(true)
	tv.SetHeaderHidden(true)
	tv.Columns().Add(walk.NewTableViewColumn())

	tunnelsView := &TunnelsView{
		TableView: tv,
		model:     model,
	}

	tunnelsView.stoppedBrush, _ = walk.NewSolidColorBrush(walk.RGB(239, 239, 239))
	tunnelsView.AddDisposable(tunnelsView.stoppedBrush)

	tunnelsView.startingBrush, _ = walk.NewSolidColorBrush(walk.RGB(255, 211, 31))
	tunnelsView.AddDisposable(tunnelsView.startingBrush)

	tunnelsView.startedBrush, _ = walk.NewSolidColorBrush(walk.RGB(0, 255, 0))
	tunnelsView.AddDisposable(tunnelsView.startedBrush)

	tunnelsView.statusPen, _ = walk.NewCosmeticPen(walk.PenSolid, walk.RGB(191, 191, 191))
	tunnelsView.AddDisposable(tunnelsView.statusPen)

	tv.SetCellStyler(tunnelsView)

	return tunnelsView, nil
}

func (tv *TunnelsView) StyleCell(style *walk.CellStyle) {
	canvas := style.Canvas()
	if canvas == nil {
		return
	}

	tunnel := tv.model.tunnels[style.Row()]

	var brush *walk.SolidColorBrush
	state, _ := tunnel.State()
	switch state {
	case service.TunnelStarted:
		brush = tv.startedBrush

	case service.TunnelStarting:
		brush = tv.startingBrush

	default:
		brush = tv.stoppedBrush
	}

	b := style.Bounds()

	b.X = b.Height
	b.Width -= b.Height
	canvas.DrawText(tunnel.Name, tv.Font(), 0, b, walk.TextVCenter)

	b.X = 4
	b.Y += 4
	b.Height -= 8
	b.Width = b.Height

	canvas.FillEllipse(brush, b)
	canvas.DrawEllipse(tv.statusPen, b)
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
		// we don't do anything with the state right now
		return
	}

	// New tunnel, add it
	tv.model.tunnels = append(tv.model.tunnels, *tunnel)
	tv.model.Sort(0, walk.SortAscending)
	for i, _ := range tv.model.tunnels {
		if tv.model.tunnels[i].Name == tunnel.Name {
			idx = i
		}
	}

	tv.model.PublishRowsInserted(idx, idx)
}
