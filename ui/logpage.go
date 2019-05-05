/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lxn/win"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
)

const (
	maxLogLinesDisplayed = 10000
)

func NewLogPage() (*LogPage, error) {
	lp := &LogPage{}

	var disposables walk.Disposables
	defer disposables.Treat()

	var err error

	if lp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(lp)

	lp.Disposing().Attach(func() {
		lp.model.quit <- true
	})

	lp.SetTitle("Log")
	lp.SetLayout(walk.NewVBoxLayout())

	if lp.logView, err = walk.NewTableView(lp); err != nil {
		return nil, err
	}
	lp.logView.SetAlternatingRowBGColor(walk.Color(win.GetSysColor(win.COLOR_BTNFACE)))
	lp.logView.SetLastColumnStretched(true)

	contextMenu, _ := walk.NewMenu()
	copyAction := walk.NewAction()
	copyAction.SetText("&Copy")
	copyAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyC})
	copyAction.Triggered().Attach(lp.onCopy)
	contextMenu.Actions().Add(copyAction)
	selectAllAction := walk.NewAction()
	selectAllAction.SetText("Select &all")
	selectAllAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyA})
	selectAllAction.Triggered().Attach(lp.onSelectAll)
	contextMenu.Actions().Add(selectAllAction)
	saveAction := walk.NewAction()
	saveAction.SetText("&Save to file")
	saveAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyS})
	saveAction.Triggered().Attach(lp.onSave)
	contextMenu.Actions().Add(saveAction)
	lp.logView.SetContextMenu(contextMenu)
	setSelectionStatus := func() {
		copyAction.SetEnabled(len(lp.logView.SelectedIndexes()) > 0)
		selectAllAction.SetEnabled(len(lp.logView.SelectedIndexes()) < len(lp.model.items))
	}
	lp.logView.SelectedIndexesChanged().Attach(setSelectionStatus)

	stampCol := walk.NewTableViewColumn()
	stampCol.SetName("Stamp")
	stampCol.SetTitle("Time")
	stampCol.SetFormat("2006-01-02 15:04:05.000")
	stampCol.SetWidth(150)
	lp.logView.Columns().Add(stampCol)

	msgCol := walk.NewTableViewColumn()
	msgCol.SetName("Line")
	msgCol.SetTitle("Log message")
	lp.logView.Columns().Add(msgCol)

	lp.model = newLogModel(lp)
	lp.logView.SetModel(lp.model)
	setSelectionStatus()

	buttonsContainer, err := walk.NewComposite(lp)
	if err != nil {
		return nil, err
	}
	buttonsContainer.SetLayout(walk.NewHBoxLayout())
	buttonsContainer.Layout().SetMargins(walk.Margins{})

	walk.NewHSpacer(buttonsContainer)

	saveButton, err := walk.NewPushButton(buttonsContainer)
	if err != nil {
		return nil, err
	}
	saveButton.SetText("Save")
	saveButton.Clicked().Attach(lp.onSave)

	disposables.Spare()

	return lp, nil
}

type LogPage struct {
	*walk.TabPage
	logView *walk.TableView
	model   *logModel
}

func (lp *LogPage) isAtBottom() bool {
	return len(lp.model.items) == 0 || lp.logView.ItemVisible(len(lp.model.items)-1)
}

func (lp *LogPage) scrollToBottom() {
	lp.logView.EnsureItemVisible(len(lp.model.items) - 1)
}

func (lp *LogPage) onCopy() {
	var logLines strings.Builder
	selectedItemIndexes := lp.logView.SelectedIndexes()
	if len(selectedItemIndexes) == 0 {
		return
	}
	for i := 0; i < len(selectedItemIndexes); i++ {
		logItem := lp.model.items[selectedItemIndexes[i]]
		logLines.WriteString(fmt.Sprintf("%s: %s\r\n", logItem.Stamp.Format("2006-01-02 15:04:05.000"), logItem.Line))
	}
	walk.Clipboard().SetText(logLines.String())
}

func (lp *LogPage) onSelectAll() {
	lp.logView.SetSelectedIndexes([]int{-1})
}

func (lp *LogPage) onSave() {
	fd := walk.FileDialog{
		Filter:   "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
		FilePath: fmt.Sprintf("wireguard-log-%s.txt", time.Now().Format("2006-01-02T150405")),
		Title:    "Export log to file",
	}

	form := lp.Form()

	if ok, _ := fd.ShowSave(form); !ok {
		return
	}

	if fd.FilterIndex == 1 && !strings.HasSuffix(fd.FilePath, ".txt") {
		fd.FilePath = fd.FilePath + ".txt"
	}

	writeFileWithOverwriteHandling(form, fd.FilePath, func(file *os.File) error {
		if _, err := ringlogger.Global.WriteTo(file); err != nil {
			return fmt.Errorf("exportLog: Ringlogger.WriteTo failed: %v", err)
		}

		return nil
	})
}

type logModel struct {
	walk.ReflectTableModelBase
	lp    *LogPage
	quit  chan bool
	items []ringlogger.FollowLine
}

func newLogModel(lp *LogPage) *logModel {
	mdl := &logModel{lp: lp, quit: make(chan bool)}
	go func() {
		ticker := time.NewTicker(time.Millisecond * 300)
		cursor := ringlogger.CursorAll

		for {
			select {
			case <-ticker.C:
				var items []ringlogger.FollowLine
				items, cursor = ringlogger.Global.FollowFromCursor(cursor)
				if len(items) == 0 {
					continue
				}
				mdl.lp.Synchronize(func() {
					isAtBottom := mdl.lp.isAtBottom() && len(lp.logView.SelectedIndexes()) <= 1

					mdl.items = append(mdl.items, items...)
					if len(mdl.items) > maxLogLinesDisplayed {
						mdl.items = mdl.items[len(mdl.items)-maxLogLinesDisplayed:]
					}
					mdl.PublishRowsReset()

					if isAtBottom {
						mdl.lp.scrollToBottom()
					}
				})

			case <-mdl.quit:
				ticker.Stop()
				break
			}
		}
	}()

	return mdl
}

func (mdl *logModel) Items() interface{} {
	return mdl.items
}
