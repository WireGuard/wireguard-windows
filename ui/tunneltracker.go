/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/service"
)

type TunnelTracker struct {
	activeTunnel        *service.Tunnel
	activeTunnelChanged walk.EventPublisher
	tunnelChangeCB      *service.TunnelChangeCallback
	inTransition        bool
}

func (tt *TunnelTracker) ActiveTunnel() *service.Tunnel {
	return tt.activeTunnel
}

func (tt *TunnelTracker) ActivateTunnel(tunnel *service.Tunnel) error {
	if tunnel == tt.activeTunnel {
		return nil
	}

	if err := tt.DeactivateTunnel(); err != nil {
		return fmt.Errorf("ActivateTunnel: Failed to deactivate tunnel '%s': %v", tunnel.Name, err)
	}

	if err := tunnel.Start(); err != nil {
		return fmt.Errorf("ActivateTunnel: Failed to start tunnel '%s': %v", tunnel.Name, err)
	}

	return nil
}

func (tt *TunnelTracker) DeactivateTunnel() error {
	if tt.activeTunnel == nil {
		return nil
	}

	state, err := tt.activeTunnel.State()
	if err != nil {
		return fmt.Errorf("DeactivateTunnel: Failed to retrieve state for tunnel %s: %v", tt.activeTunnel.Name, err)
	}

	if state == service.TunnelStarted {
		if err := tt.activeTunnel.Stop(); err != nil {
			return fmt.Errorf("DeactivateTunnel: Failed to stop tunnel '%s': %v", tt.activeTunnel.Name, err)
		}
	}

	if state == service.TunnelStarted || state == service.TunnelStopping {
		if err := tt.activeTunnel.WaitForStop(); err != nil {
			return fmt.Errorf("DeactivateTunnel: Failed to wait for tunnel '%s' to stop: %v", tt.activeTunnel.Name, err)
		}
	}

	return nil
}

func (tt *TunnelTracker) ActiveTunnelChanged() *walk.Event {
	return tt.activeTunnelChanged.Event()
}

func (tt *TunnelTracker) InTransition() bool {
	return tt.inTransition
}

func (tt *TunnelTracker) SetTunnelState(tunnel *service.Tunnel, state service.TunnelState, err error) {
	if err != nil {
		tt.inTransition = false
	}

	switch state {
	case service.TunnelStarted:
		tt.inTransition = false
		tt.activeTunnel = tunnel

	case service.TunnelStarting, service.TunnelStopping:
		tt.inTransition = true

	case service.TunnelStopped:
		if tt.activeTunnel != nil && tt.activeTunnel.Name == tunnel.Name {
			tt.inTransition = false
		}
		tt.activeTunnel = nil

	default:
		return
	}

	tt.activeTunnelChanged.Publish()
}
