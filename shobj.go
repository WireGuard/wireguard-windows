// Copyright 2012 The Walk Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winapi

import (
	"fmt"
	"syscall"
	"unsafe"
)

type ITaskbarList3Vtbl struct {
	QueryInterface         uintptr
	AddRef                 uintptr
	Release                uintptr
    HrInit                 uintptr
	AddTab                 uintptr
    DeleteTab              uintptr
    ActivateTab            uintptr
	SetActiveAlt           uintptr
	MarkFullscreenWindow   uintptr
	SetProgressValue       uintptr
	SetProgressState       uintptr
	RegisterTab            uintptr
	UnregisterTab          uintptr
	SetTabOrder            uintptr
	SetTabActive           uintptr
	ThumbBarAddButtons     uintptr
	ThumbBarUpdateButtons  uintptr
	ThumbBarSetImageList   uintptr
	SetOverlayIcon         uintptr
	SetThumbnailTooltip    uintptr
	SetThumbnailClip       uintptr
}

type ITaskbarList3 struct {
    LpVtbl *ITaskbarList3Vtbl
} 