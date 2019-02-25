/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"

	"golang.zx2c4.com/wireguard/windows/ui/internal/walk"
	"golang.zx2c4.com/wireguard/windows/ui/internal/walk/win"
)

// #include "syntaxedit.h"
import "C"

type PrivateKeyHandler func(privateKey string)
type PrivateKeyEvent struct {
	handlers []PrivateKeyHandler
}

func (e *PrivateKeyEvent) Attach(handler PrivateKeyHandler) int {
	for i, h := range e.handlers {
		if h == nil {
			e.handlers[i] = handler
			return i
		}
	}

	e.handlers = append(e.handlers, handler)
	return len(e.handlers) - 1
}
func (e *PrivateKeyEvent) Detach(handle int) {
	e.handlers[handle] = nil
}

type PrivateKeyPublisher struct {
	event PrivateKeyEvent
}

func (p *PrivateKeyPublisher) Event() *PrivateKeyEvent {
	return &p.event
}
func (p *PrivateKeyPublisher) Publish(privateKey string) {
	for _, handler := range p.event.handlers {
		if handler != nil {
			handler(privateKey)
		}
	}
}

type SyntaxEdit struct {
	walk.WidgetBase
	textChangedPublisher walk.EventPublisher
	privateKeyPublisher  PrivateKeyPublisher
}

func init() {
	C.register_syntax_edit()
}

func (se *SyntaxEdit) LayoutFlags() walk.LayoutFlags {
	return walk.GrowableHorz | walk.GrowableVert | walk.GreedyHorz | walk.GreedyVert
}

func (se *SyntaxEdit) MinSizeHint() walk.Size {
	return walk.Size{20, 12}
}

func (se *SyntaxEdit) SizeHint() walk.Size {
	return walk.Size{200, 100}
}

func (se *SyntaxEdit) Text() string {
	textLength := se.SendMessage(win.WM_GETTEXTLENGTH, 0, 0)
	buf := make([]uint16, textLength+1)
	se.SendMessage(win.WM_GETTEXT, uintptr(textLength+1), uintptr(unsafe.Pointer(&buf[0])))
	return strings.Replace(syscall.UTF16ToString(buf), "\r\n", "\n", -1)
}

func (se *SyntaxEdit) SetText(text string) (err error) {
	if text == se.Text() {
		return nil
	}
	text = strings.Replace(text, "\n", "\r\n", -1)
	if win.TRUE != se.SendMessage(win.WM_SETTEXT, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(text)))) {
		err = errors.New("WM_SETTEXT failed")
	}
	se.textChangedPublisher.Publish()
	return
}

func (se *SyntaxEdit) TextChanged() *walk.Event {
	return se.textChangedPublisher.Event()
}

func (se *SyntaxEdit) PrivateKeyChanged() *PrivateKeyEvent {
	return se.privateKeyPublisher.Event()
}

func (se *SyntaxEdit) WndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_NOTIFY, win.WM_COMMAND:
		switch win.HIWORD(uint32(wParam)) {
		case win.EN_CHANGE:
			se.textChangedPublisher.Publish()
		}
		// This is a horrible trick from MFC where we reflect the event back to the child.
		se.SendMessage(msg+C.WM_REFLECT, wParam, lParam)
	case C.SE_PRIVATE_KEY:
		if lParam == 0 {
			se.privateKeyPublisher.Publish("")
		} else {
			se.privateKeyPublisher.Publish(C.GoString((*C.char)(unsafe.Pointer(lParam))))
		}
	}
	return se.WidgetBase.WndProc(hwnd, msg, wParam, lParam)
}

func NewSyntaxEdit(parent walk.Container) (*SyntaxEdit, error) {
	se := &SyntaxEdit{}
	err := walk.InitWidget(
		se,
		parent,
		"WgQuickSyntaxEdit",
		C.SYNTAXEDIT_STYLE,
		C.SYNTAXEDIT_EXTSTYLE,
	)
	if err != nil {
		return nil, err
	}

	se.GraphicsEffects().Add(walk.InteractionEffect)
	se.GraphicsEffects().Add(walk.FocusEffect)
	se.MustRegisterProperty("Text", walk.NewProperty(
		func() interface{} {
			return se.Text()
		},
		func(v interface{}) error {
			if s, ok := v.(string); ok {
				return se.SetText(s)
			} else {
				return se.SetText("")
			}
		},
		se.textChangedPublisher.Event()))

	return se, nil
}
