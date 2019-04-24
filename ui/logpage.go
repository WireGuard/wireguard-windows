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

func NewLogPage(logger *ringlogger.Ringlogger) (*LogPage, error) {
	lp := &LogPage{logger: logger}

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
	lp.Layout().SetMargins(walk.Margins{18, 18, 18, 18})

	if lp.logView, err = walk.NewTableView(lp); err != nil {
		return nil, err
	}
	lp.logView.SetAlternatingRowBGColor(walk.Color(win.GetSysColor(win.COLOR_BTNFACE)))
	lp.logView.SetLastColumnStretched(true)

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

	lp.model = newLogModel(lp, logger)
	lp.logView.SetModel(lp.model)

	buttonsContainer, err := walk.NewComposite(lp)
	if err != nil {
		return nil, err
	}
	buttonsContainer.SetLayout(walk.NewHBoxLayout())
	buttonsContainer.Layout().SetMargins(walk.Margins{0, 12, 0, 0})

	walk.NewHSpacer(buttonsContainer)

	saveButton, err := walk.NewPushButton(buttonsContainer)
	if err != nil {
		return nil, err
	}
	saveButton.SetText("Save")
	saveButton.Clicked().Attach(lp.onSaveButtonClicked)

	disposables.Spare()

	return lp, nil
}

type LogPage struct {
	*walk.TabPage
	logView *walk.TableView
	logger  *ringlogger.Ringlogger
	model   *logModel
}

func (lp *LogPage) isAtBottom() bool {
	return lp.logView.ItemVisible(len(lp.model.items) - 1)
}

func (lp *LogPage) scrollToBottom() {
	lp.logView.EnsureItemVisible(len(lp.model.items) - 1)
}

func (lp *LogPage) onSaveButtonClicked() {
	fd := walk.FileDialog{
		Filter:   "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
		FilePath: fmt.Sprintf("wireguard-log-%s.txt", time.Now().Format("2006-01-02T150405")),
		Title:    "Export log to file",
	}

	form := lp.Form()

	if ok, _ := fd.ShowSave(form); !ok {
		return
	}

	extensions := []string{".log", ".txt"}
	if fd.FilterIndex < 3 && !strings.HasSuffix(fd.FilePath, extensions[fd.FilterIndex-1]) {
		fd.FilePath = fd.FilePath + extensions[fd.FilterIndex-1]
	}

	writeFileWithOverwriteHandling(form, fd.FilePath, func(file *os.File) error {
		if _, err := lp.logger.WriteTo(file); err != nil {
			return fmt.Errorf("exportLog: Ringlogger.WriteTo failed: %v", err)
		}

		return nil
	})
}

type logModel struct {
	walk.ReflectTableModelBase
	lp     *LogPage
	quit   chan bool
	logger *ringlogger.Ringlogger
	items  []ringlogger.FollowLine
}

func newLogModel(lp *LogPage, logger *ringlogger.Ringlogger) *logModel {
	mdl := &logModel{lp: lp, quit: make(chan bool), logger: logger}
	var lastCursor uint32
	mdl.items, lastCursor = logger.FollowFromCursor(ringlogger.CursorAll)

	var lastStamp time.Time
	if len(mdl.items) > 0 {
		lastStamp = mdl.items[len(mdl.items)-1].Stamp
	}

	go func() {
		ticker := time.NewTicker(time.Second)

		for {
			select {
			case <-ticker.C:
				items, cursor := mdl.logger.FollowFromCursor(ringlogger.CursorAll)

				var stamp time.Time
				if len(items) > 0 {
					stamp = items[len(items)-1].Stamp
				}

				if cursor != lastCursor || stamp.After(lastStamp) {
					lastCursor = cursor
					lastStamp = stamp

					mdl.lp.Synchronize(func() {
						isAtBottom := mdl.lp.isAtBottom()

						mdl.items = items
						mdl.PublishRowsReset()

						if isAtBottom {
							mdl.lp.scrollToBottom()
						}
					})
				}

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
