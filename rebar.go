// Copyright 2010 The Walk Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package walk

import (
	"syscall"
	"unsafe"

	"github.com/lxn/win"
)

type ReBar struct {
	WidgetBase
	toolBar *ToolBar
}

func NewReBar(parent Container, toolBar *ToolBar) (*ReBar, error) {
	rb := &ReBar{}

	if err := InitWidget(
		rb,
		parent,
		"ReBarWindow32",
		win.WS_CHILD|
			win.WS_VISIBLE|
			win.WS_CLIPSIBLINGS|
			win.WS_CLIPCHILDREN|
			RBS_VARHEIGHT|
			RBS_BANDBORDERS|
			win.CCS_NODIVIDER|
			win.CCS_BOTTOM,
		win.WS_EX_TOOLWINDOW); err != nil {
		return nil, err
	}

	rb.toolBar = toolBar

	rbbi := ReBarBandInfo{}
	rbbi.FMask = RBBIM_STYLE | // fStyle is valid.
		RBBIM_TEXT | // lpText is valid.
		RBBIM_CHILD | // hwndChild is valid.
		RBBIM_CHILDSIZE | // child size members are valid.
		RBBIM_SIZE // cx is valid
	rbbi.FStyle = RBBS_CHILDEDGE | RBBS_GRIPPERALWAYS

	// https://docs.microsoft.com/en-us/windows/desktop/controls/create-rebar-controls

	// Set values unique to the band with the toolbar.
	rbbi.LpText = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("")))
	rbbi.HwndChild = toolBar.hWnd
	rbbi.CyChild = uint32(100)
	rbbi.CxMinChild = uint32(100)
	rbbi.CyMinChild = uint32(100)
	rbbi.Cx = uint32(0)

	rb.SendMessage(RB_INSERTBAND, 0, uintptr(unsafe.Pointer(&rbbi)))

	return rb, nil
}

const (
	RBS_VARHEIGHT       = 0x0200
	RBS_BANDBORDERS     = 0x0400
	RBS_AUTOSIZE        = 0x2000
	RBS_VERTICALGRIPPER = 0x4000
)

const (
	RB_INSERTBAND   = win.WM_USER + 1
	RB_DELETEBAND   = win.WM_USER + 2
	RB_SETBARINFO   = win.WM_USER + 4
	RB_GETBANDINFO  = win.WM_USER + 5
	RB_SETBANDINFO  = win.WM_USER + 6
	RB_HITTEST      = win.WM_USER + 8
	RB_GETRECT      = win.WM_USER + 9
	RB_GETBANDCOUNT = win.WM_USER + 12
	RB_GETROWCOUNT  = win.WM_USER + 13
	RB_GETROWHEIGHT = win.WM_USER + 14
	RB_GETBARHEIGHT = win.WM_USER + 27
)

const (
	RBBIM_STYLE      = 0x00000001
	RBBIM_COLORS     = 0x00000002
	RBBIM_TEXT       = 0x00000004
	RBBIM_IMAGE      = 0x00000008
	RBBIM_CHILD      = 0x00000010
	RBBIM_CHILDSIZE  = 0x00000020
	RBBIM_SIZE       = 0x00000040
	RBBIM_BACKGROUND = 0x00000080
	RBBIM_ID         = 0x00000100
	RBBIM_IDEALSIZE  = 0x00000200
	RBBIM_LPARAM     = 0x00000400
	RBBIM_HEADERSIZE = 0x00000800
)

const (
	RBBS_BREAK          = 0x00000001
	RBBS_FIXEDSIZE      = 0x00000002
	RBBS_CHILDEDGE      = 0x00000004
	RBBS_HIDDEN         = 0x00000008
	RBBS_NOVERT         = 0x00000010
	RBBS_FIXEDBMP       = 0x00000020
	RBBS_VARIABLEHEIGHT = 0x00000040
	RBBS_GRIPPERALWAYS  = 0x00000080
	RBBS_NOGRIPPER      = 0x00000100
	RBBS_USECHEVRON     = 0x00000200
	RBBS_HIDETITLE      = 0x00000400
)

func (rb *ReBar) LayoutFlags() LayoutFlags {
	return ShrinkableHorz | GrowableHorz
}

func (rb *ReBar) ToolBar() *ToolBar {
	return rb.toolBar
}

func (rb *ReBar) MinSizeHint() Size {
	return rb.SizeHint()
}

func (rb *ReBar) SizeHint() Size {
	// Fetch from toolbar
	return Size{100, 100}
}

type ReBarBandInfo struct {
	CbSize            uint32
	FMask             uint32
	FStyle            uint32
	ClrFore           win.COLORREF
	ClrBack           win.COLORREF
	LpText            uintptr
	Cch               uint32
	IImage            int32
	HwndChild         win.HWND
	CxMinChild        uint32
	CyMinChild        uint32
	Cx                uint32
	HbmBack           win.HBITMAP
	WID               uint32
	CyChild           uint32
	CyMaxChild        uint32
	CyIntegral        uint32
	CxIdeal           uint32
	LParam            uintptr
	CxHeader          uint32
	RcChevronLocation win.RECT
	UChevronState     uint32
}
