/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package syntax

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

type SyntaxEdit struct {
	walk.WidgetBase
	irich                           *win.IRichEditOle
	idoc                            *win.ITextDocument
	lastBlockState                  BlockState
	yheight                         int
	highlightGuard                  uint32
	textChangedPublisher            walk.EventPublisher
	privateKeyPublisher             walk.StringEventPublisher
	blockUntunneledTrafficPublisher walk.IntEventPublisher
}

type BlockState int

const (
	InevaluableBlockingUntunneledTraffic BlockState = iota
	BlockingUntunneledTraffic
	NotBlockingUntunneledTraffic
)

func (se *SyntaxEdit) LayoutFlags() walk.LayoutFlags {
	return walk.GrowableHorz | walk.GrowableVert | walk.GreedyHorz | walk.GreedyVert
}

func (se *SyntaxEdit) MinSizeHint() walk.Size {
	return walk.Size{20, 12}
}

func (se *SyntaxEdit) SizeHint() walk.Size {
	return walk.Size{200, 100}
}

func (*SyntaxEdit) CreateLayoutItem(ctx *walk.LayoutContext) walk.LayoutItem {
	return walk.NewGreedyLayoutItem()
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
	return
}

func (se *SyntaxEdit) TextChanged() *walk.Event {
	return se.textChangedPublisher.Event()
}

func (se *SyntaxEdit) PrivateKeyChanged() *walk.StringEvent {
	return se.privateKeyPublisher.Event()
}

func (se *SyntaxEdit) BlockUntunneledTrafficStateChanged() *walk.IntEvent {
	return se.blockUntunneledTrafficPublisher.Event()
}

type spanStyle struct {
	color   win.COLORREF
	effects uint32
}

var stylemap = map[highlight]spanStyle{
	highlightSection:      spanStyle{color: win.RGB(0x32, 0x6D, 0x74), effects: win.CFE_BOLD},
	highlightField:        spanStyle{color: win.RGB(0x9B, 0x23, 0x93), effects: win.CFE_BOLD},
	highlightPrivateKey:   spanStyle{color: win.RGB(0x64, 0x38, 0x20)},
	highlightPublicKey:    spanStyle{color: win.RGB(0x64, 0x38, 0x20)},
	highlightPresharedKey: spanStyle{color: win.RGB(0x64, 0x38, 0x20)},
	highlightIP:           spanStyle{color: win.RGB(0x0E, 0x0E, 0xFF)},
	highlightCidr:         spanStyle{color: win.RGB(0x81, 0x5F, 0x03)},
	highlightHost:         spanStyle{color: win.RGB(0x0E, 0x0E, 0xFF)},
	highlightPort:         spanStyle{color: win.RGB(0x81, 0x5F, 0x03)},
	highlightMTU:          spanStyle{color: win.RGB(0x1C, 0x00, 0xCF)},
	highlightKeepalive:    spanStyle{color: win.RGB(0x1C, 0x00, 0xCF)},
	highlightComment:      spanStyle{color: win.RGB(0x53, 0x65, 0x79), effects: win.CFE_ITALIC},
	highlightDelimiter:    spanStyle{color: win.RGB(0x00, 0x00, 0x00)},
	highlightCmd:          spanStyle{color: win.RGB(0x63, 0x75, 0x89)},
	highlightError:        spanStyle{color: win.RGB(0xC4, 0x1A, 0x16), effects: win.CFE_UNDERLINE},
}

func (se *SyntaxEdit) evaluateUntunneledBlocking(cfg string, spans []highlightSpan) {
	state := InevaluableBlockingUntunneledTraffic
	var onAllowedIPs,
		seenPeer,
		seen00v6,
		seen00v4,
		seen01v6,
		seen80001v6,
		seen01v4,
		seen1281v4 bool

	for i := range spans {
		span := &spans[i]
		switch span.t {
		case highlightError:
			goto done
		case highlightSection:
			if !strings.EqualFold(cfg[span.s:span.s+span.len], "[Peer]") {
				break
			}
			if !seenPeer {
				seenPeer = true
			} else {
				goto done
			}
			break
		case highlightField:
			onAllowedIPs = strings.EqualFold(cfg[span.s:span.s+span.len], "AllowedIPs")
			break
		case highlightIP:
			if !onAllowedIPs || !seenPeer {
				break
			}
			if i+2 >= len(spans) || spans[i+1].t != highlightDelimiter || spans[i+2].t != highlightCidr {
				break
			}
			if spans[i+2].len != 1 {
				break
			}
			switch cfg[spans[i+2].s] {
			case '0':
				switch cfg[span.s : span.s+span.len] {
				case "0.0.0.0":
					seen00v4 = true
				case "::":
					seen00v6 = true
				}
			case '1':
				switch cfg[span.s : span.s+span.len] {
				case "0.0.0.0":
					seen01v4 = true
				case "128.0.0.0":
					seen1281v4 = true
				case "::":
					seen01v6 = true
				case "8000::":
					seen80001v6 = true
				}
			}
			break
		}
	}

	if seen00v4 || seen00v6 {
		state = BlockingUntunneledTraffic
	} else if (seen01v4 && seen1281v4) || (seen01v6 && seen80001v6) {
		state = NotBlockingUntunneledTraffic
	}

done:
	if state != se.lastBlockState {
		se.blockUntunneledTrafficPublisher.Publish(int(state))
		se.lastBlockState = state
	}
}

func (se *SyntaxEdit) highlightText() error {
	if !atomic.CompareAndSwapUint32(&se.highlightGuard, 0, 1) {
		return nil
	}
	defer atomic.StoreUint32(&se.highlightGuard, 0)

	hWnd := se.Handle()
	gettextlengthex := win.GETTEXTLENGTHEX{
		Flags:    win.GTL_NUMBYTES,
		Codepage: win.CP_ACP, // Probably CP_UTF8 would be better, but (wine at least) returns utf32 sizes.
	}
	msgSize := uint32(win.SendMessage(hWnd, win.EM_GETTEXTLENGTHEX, uintptr(unsafe.Pointer(&gettextlengthex)), 0))
	if msgSize == win.E_INVALIDARG {
		return errors.New("Failed to get text length")
	}

	gettextex := win.GETTEXTEX{
		Flags:    win.GT_NOHIDDENTEXT,
		Codepage: gettextlengthex.Codepage,
		Cb:       msgSize + 1,
	}
	msg := make([]byte, msgSize+1)
	msgCount := win.SendMessage(hWnd, win.EM_GETTEXTEX, uintptr(unsafe.Pointer(&gettextex)), uintptr(unsafe.Pointer(&msg[0])))
	if msgCount < 0 {
		return errors.New("Failed to get text")
	}
	cfg := strings.Replace(string(msg[:msgCount]), "\r", "\n", -1)

	spans := highlightConfig(cfg)
	se.evaluateUntunneledBlocking(cfg, spans)

	se.idoc.Undo(win.TomSuspend, nil)
	win.SendMessage(hWnd, win.EM_SETEVENTMASK, 0, 0)
	win.SendMessage(hWnd, win.WM_SETREDRAW, win.FALSE, 0)
	var origSelection win.CHARRANGE
	win.SendMessage(hWnd, win.EM_EXGETSEL, 0, uintptr(unsafe.Pointer(&origSelection)))
	var origScroll win.POINT
	win.SendMessage(hWnd, win.EM_GETSCROLLPOS, 0, uintptr(unsafe.Pointer(&origScroll)))
	win.SendMessage(hWnd, win.EM_HIDESELECTION, win.TRUE, 0)
	format := win.CHARFORMAT2{
		CHARFORMAT: win.CHARFORMAT{
			CbSize:    uint32(unsafe.Sizeof(win.CHARFORMAT2{})),
			DwMask:    win.CFM_COLOR | win.CFM_CHARSET | win.CFM_SIZE | win.CFM_BOLD | win.CFM_ITALIC | win.CFM_UNDERLINE,
			DwEffects: win.CFE_AUTOCOLOR,
			BCharSet:  win.ANSI_CHARSET,
		},
	}
	if se.yheight != 0 {
		format.YHeight = 20 * 10
	}
	win.SendMessage(hWnd, win.EM_SETCHARFORMAT, win.SCF_ALL, uintptr(unsafe.Pointer(&format)))
	bgColor := win.COLORREF(win.GetSysColor(win.COLOR_WINDOW))
	bgInversion := (bgColor & win.RGB(0xFF, 0xFF, 0xFF)) ^ win.RGB(0xFF, 0xFF, 0xFF)
	win.SendMessage(hWnd, win.EM_SETBKGNDCOLOR, 0, uintptr(bgColor))
	numSpans := len(spans)
	foundPrivateKey := false
	for i := range spans {
		span := &spans[i]
		if numSpans <= 2048 {
			selection := win.CHARRANGE{int32(span.s), int32(span.s + span.len)}
			win.SendMessage(hWnd, win.EM_EXSETSEL, 0, uintptr(unsafe.Pointer(&selection)))
			format.CrTextColor = stylemap[span.t].color ^ bgInversion
			format.DwEffects = stylemap[span.t].effects
			win.SendMessage(hWnd, win.EM_SETCHARFORMAT, win.SCF_SELECTION, uintptr(unsafe.Pointer(&format)))
		}
		if span.t == highlightPrivateKey && !foundPrivateKey {
			privateKey := cfg[span.s : span.s+span.len]
			se.privateKeyPublisher.Publish(privateKey)
			foundPrivateKey = true
		}
	}
	win.SendMessage(hWnd, win.EM_SETSCROLLPOS, 0, uintptr(unsafe.Pointer(&origScroll)))
	win.SendMessage(hWnd, win.EM_EXSETSEL, 0, uintptr(unsafe.Pointer(&origSelection)))
	win.SendMessage(hWnd, win.EM_HIDESELECTION, win.FALSE, 0)
	win.SendMessage(hWnd, win.WM_SETREDRAW, win.TRUE, 0)
	win.RedrawWindow(hWnd, nil, 0, win.RDW_ERASE|win.RDW_FRAME|win.RDW_INVALIDATE|win.RDW_ALLCHILDREN)
	win.SendMessage(hWnd, win.EM_SETEVENTMASK, 0, win.ENM_CHANGE)
	se.idoc.Undo(win.TomResume, nil)
	if !foundPrivateKey {
		se.privateKeyPublisher.Publish("")
	}
	return nil
}

func (se *SyntaxEdit) contextMenu(x, y int32) error {
	/* This disturbing hack grabs the system edit menu normally used for the EDIT control. */
	comctl32UTF16, err := windows.UTF16PtrFromString("comctl32.dll")
	if err != nil {
		return err
	}
	comctl32Handle := win.GetModuleHandle(comctl32UTF16)
	if comctl32Handle == 0 {
		return errors.New("Failed to get comctl32.dll handle")
	}
	menu := win.LoadMenu(comctl32Handle, win.MAKEINTRESOURCE(1))
	if menu == 0 {
		return errors.New("Failed to load menu")
	}
	defer win.DestroyMenu(menu)

	hWnd := se.Handle()
	enableWhenSelected := uint32(win.MF_GRAYED)
	var selection win.CHARRANGE
	win.SendMessage(hWnd, win.EM_EXGETSEL, 0, uintptr(unsafe.Pointer(&selection)))
	if selection.CpMin < selection.CpMax {
		enableWhenSelected = win.MF_ENABLED
	}
	enableSelectAll := uint32(win.MF_GRAYED)
	gettextlengthex := win.GETTEXTLENGTHEX{
		Flags:    win.GTL_DEFAULT,
		Codepage: win.CP_ACP,
	}
	if selection.CpMin != 0 || (selection.CpMax < int32(win.SendMessage(hWnd, win.EM_GETTEXTLENGTHEX, uintptr(unsafe.Pointer(&gettextlengthex)), 0))) {
		enableSelectAll = win.MF_ENABLED
	}
	enableUndo := uint32(win.MF_GRAYED)
	if win.SendMessage(hWnd, win.EM_CANUNDO, 0, 0) != 0 {
		enableUndo = win.MF_ENABLED
	}
	enablePaste := uint32(win.MF_GRAYED)
	if win.SendMessage(hWnd, win.EM_CANPASTE, win.CF_TEXT, 0) != 0 {
		enablePaste = win.MF_ENABLED
	}

	popup := win.GetSubMenu(menu, 0)
	win.EnableMenuItem(popup, win.WM_UNDO, win.MF_BYCOMMAND|enableUndo)
	win.EnableMenuItem(popup, win.WM_CUT, win.MF_BYCOMMAND|enableWhenSelected)
	win.EnableMenuItem(popup, win.WM_COPY, win.MF_BYCOMMAND|enableWhenSelected)
	win.EnableMenuItem(popup, win.WM_PASTE, win.MF_BYCOMMAND|enablePaste)
	win.EnableMenuItem(popup, win.WM_CLEAR, win.MF_BYCOMMAND|enableWhenSelected)
	win.EnableMenuItem(popup, win.EM_SETSEL, win.MF_BYCOMMAND|enableSelectAll)

	// Delete items that we don't handle.
	for ctl := win.GetMenuItemCount(popup) - 1; ctl >= 0; ctl-- {
		menuItem := win.MENUITEMINFO{
			CbSize: uint32(unsafe.Sizeof(win.MENUITEMINFO{})),
			FMask:  win.MIIM_FTYPE | win.MIIM_ID,
		}
		if !win.GetMenuItemInfo(popup, uint32(ctl), win.MF_BYPOSITION, &menuItem) {
			continue
		}
		if (menuItem.FType & win.MFT_SEPARATOR) != 0 {
			continue
		}
		switch menuItem.WID {
		case win.WM_UNDO, win.WM_CUT, win.WM_COPY, win.WM_PASTE, win.WM_CLEAR, win.EM_SETSEL:
			continue
		}
		win.DeleteMenu(popup, uint32(ctl), win.MF_BYPOSITION)
	}
	// Delete trailing and adjacent separators.
	end := true
	for ctl := win.GetMenuItemCount(popup) - 1; ctl >= 0; ctl-- {
		menuItem := win.MENUITEMINFO{
			CbSize: uint32(unsafe.Sizeof(win.MENUITEMINFO{})),
			FMask:  win.MIIM_FTYPE,
		}
		if !win.GetMenuItemInfo(popup, uint32(ctl), win.MF_BYPOSITION, &menuItem) {
			continue
		}
		if (menuItem.FType & win.MFT_SEPARATOR) == 0 {
			end = false
			continue
		}
		if !end && ctl > 0 {
			if !win.GetMenuItemInfo(popup, uint32(ctl-1), win.MF_BYPOSITION, &menuItem) {
				continue
			}
			if (menuItem.FType & win.MFT_SEPARATOR) == 0 {
				continue
			}
		}
		win.DeleteMenu(popup, uint32(ctl), win.MF_BYPOSITION)
	}

	if x == -1 && y == -1 {
		var rect win.RECT
		win.GetWindowRect(hWnd, &rect)
		x = (rect.Left + rect.Right) / 2
		y = (rect.Top + rect.Bottom) / 2
	}

	if win.GetFocus() != hWnd {
		win.SetFocus(hWnd)
	}

	cmd := win.TrackPopupMenu(popup, win.TPM_LEFTALIGN|win.TPM_RIGHTBUTTON|win.TPM_RETURNCMD|win.TPM_NONOTIFY, x, y, 0, hWnd, nil)
	if cmd != 0 {
		lParam := uintptr(0)
		if cmd == win.EM_SETSEL {
			lParam = ^uintptr(0)
		}
		win.SendMessage(hWnd, cmd, 0, lParam)
	}

	return nil
}

func (*SyntaxEdit) NeedsWmSize() bool {
	return true
}

func (se *SyntaxEdit) WndProc(hWnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_DESTROY:
		if se.idoc != nil {
			se.idoc.Release()
		}
		if se.irich != nil {
			se.irich.Release()
		}

	case win.WM_SETTEXT:
		ret := se.WidgetBase.WndProc(hWnd, msg, wParam, lParam)
		se.highlightText()
		win.SendMessage(hWnd, win.EM_EMPTYUNDOBUFFER, 0, 0)
		se.textChangedPublisher.Publish()
		return ret

	case win.WM_COMMAND, win.WM_NOTIFY:
		switch win.HIWORD(uint32(wParam)) {
		case win.EN_CHANGE:
			se.highlightText()
			se.textChangedPublisher.Publish()
		}

	case win.WM_PASTE:
		win.SendMessage(hWnd, win.EM_PASTESPECIAL, win.CF_TEXT, 0)
		return 0

	case win.WM_KEYDOWN:
		key := win.LOWORD(uint32(wParam))
		if key == 'V' && win.GetKeyState(win.VK_CONTROL) < 0 ||
			key == win.VK_INSERT && win.GetKeyState(win.VK_SHIFT) < 0 {
			win.SendMessage(hWnd, win.EM_PASTESPECIAL, win.CF_TEXT, 0)
			return 0
		}

	case win.WM_CONTEXTMENU:
		se.contextMenu(win.GET_X_LPARAM(lParam), win.GET_Y_LPARAM(lParam))
		return 0

	case win.WM_THEMECHANGED:
		se.highlightText()

	case win.WM_GETDLGCODE:
		m := (*win.MSG)(unsafe.Pointer(lParam))
		ret := se.WidgetBase.WndProc(hWnd, msg, wParam, lParam)
		ret &^= win.DLGC_WANTTAB
		if m != nil && m.Message == win.WM_KEYDOWN && m.WParam == win.VK_TAB && win.GetKeyState(win.VK_CONTROL) >= 0 {
			ret &^= win.DLGC_WANTMESSAGE
		}
		return ret
	}

	return se.WidgetBase.WndProc(hWnd, msg, wParam, lParam)
}

func NewSyntaxEdit(parent walk.Container) (*SyntaxEdit, error) {
	const LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
	_, err := windows.LoadLibraryEx("msftedit.dll", 0, LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, fmt.Errorf("Failed to load msftedit.dll: %v", err)
	}

	se := &SyntaxEdit{}
	if err := walk.InitWidget(
		se,
		parent,
		win.MSFTEDIT_CLASS,
		win.WS_CHILD|win.ES_MULTILINE|win.WS_VISIBLE|win.WS_VSCROLL|win.WS_BORDER|win.WS_HSCROLL|win.WS_TABSTOP|win.ES_WANTRETURN|win.ES_NOOLEDRAGDROP,
		0); err != nil {
		return nil, err
	}
	hWnd := se.Handle()
	win.SetWindowLong(hWnd, win.GWL_EXSTYLE, win.GetWindowLong(hWnd, win.GWL_EXSTYLE)&^win.WS_EX_CLIENTEDGE)
	win.SendMessage(hWnd, win.EM_GETOLEINTERFACE, 0, uintptr(unsafe.Pointer(&se.irich)))
	var idoc unsafe.Pointer
	se.irich.QueryInterface(&win.IID_ITextDocument, &idoc)
	se.idoc = (*win.ITextDocument)(idoc)
	win.SendMessage(hWnd, win.EM_SETEVENTMASK, 0, win.ENM_CHANGE)
	win.SendMessage(hWnd, win.EM_SETTEXTMODE, win.TM_SINGLECODEPAGE, 0)
	se.ApplyDPI(parent.DPI())
	se.GraphicsEffects().Add(walk.InteractionEffect)
	se.GraphicsEffects().Add(walk.FocusEffect)
	se.MustRegisterProperty("Text", walk.NewProperty(
		func() interface{} {
			return se.Text()
		},
		func(v interface{}) error {
			if s, ok := v.(string); ok {
				return se.SetText(s)
			}
			return se.SetText("")
		},
		se.textChangedPublisher.Event()))
	return se, nil
}

func (se *SyntaxEdit) ApplyDPI(dpi int) {
	hWnd := se.Handle()
	hdc := win.GetDC(hWnd)
	logPixels := win.GetDeviceCaps(hdc, win.LOGPIXELSY)
	if se.yheight != 0 {
		win.SendMessage(hWnd, win.EM_SETZOOM, uintptr(logPixels), uintptr(dpi))
	}
	se.yheight = 20 * 10 * dpi / int(logPixels)
	win.ReleaseDC(hWnd, hdc)
	se.highlightText()
}
