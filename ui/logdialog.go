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

func runLogDialog(owner walk.Form, logger *ringlogger.Ringlogger) {
	dlg := &LogDialog{logger: logger}
	dlg.model = newLogModel(dlg, logger)
	defer func() {
		dlg.model.quit <- true
	}()

	var disposables walk.Disposables
	defer disposables.Treat()

	showError := func(err error) bool {
		if err == nil {
			return false
		}

		walk.MsgBox(owner, "Viewing log dialog failed", err.Error(), walk.MsgBoxIconError)

		return true
	}

	var err error

	if dlg.Dialog, err = walk.NewDialog(owner); showError(err) {
		return
	}
	disposables.Add(dlg)

	dlg.SetTitle("WireGuard Log")
	dlg.SetLayout(walk.NewVBoxLayout())
	dlg.Layout().SetMargins(walk.Margins{18, 18, 18, 18})
	dlg.SetMinMaxSize(walk.Size{600, 400}, walk.Size{})

	if dlg.logView, err = walk.NewTableView(dlg); showError(err) {
		return
	}
	dlg.logView.SetAlternatingRowBGColor(walk.Color(win.GetSysColor(win.COLOR_BTNFACE)))
	dlg.logView.SetLastColumnStretched(true)

	stampCol := walk.NewTableViewColumn()
	stampCol.SetName("Stamp")
	stampCol.SetTitle("Time")
	stampCol.SetFormat("2006-01-02 15:04:05.000")
	stampCol.SetWidth(150)
	dlg.logView.Columns().Add(stampCol)

	msgCol := walk.NewTableViewColumn()
	msgCol.SetName("Line")
	msgCol.SetTitle("Log message")
	dlg.logView.Columns().Add(msgCol)

	dlg.logView.SetModel(dlg.model)
	dlg.scrollToBottom()

	buttonsContainer, err := walk.NewComposite(dlg)
	buttonsContainer.SetLayout(walk.NewHBoxLayout())
	buttonsContainer.Layout().SetMargins(walk.Margins{0, 12, 0, 0})

	saveButton, err := walk.NewPushButton(buttonsContainer)
	saveButton.SetText("Save")
	saveButton.Clicked().Attach(dlg.onSaveButtonClicked)

	walk.NewHSpacer(buttonsContainer)

	closeButton, err := walk.NewPushButton(buttonsContainer)
	closeButton.SetText("Close")
	closeButton.Clicked().Attach(dlg.Accept)

	dlg.SetDefaultButton(closeButton)
	dlg.SetCancelButton(closeButton)

	disposables.Spare()

	dlg.Run()
}

type LogDialog struct {
	*walk.Dialog
	logView *walk.TableView
	logger  *ringlogger.Ringlogger
	model   *logModel
}

func (dlg *LogDialog) isAtBottom() bool {
	return dlg.logView.ItemVisible(len(dlg.model.items) - 1)
}

func (dlg *LogDialog) scrollToBottom() {
	dlg.logView.EnsureItemVisible(len(dlg.model.items) - 1)
}

func (dlg *LogDialog) onSaveButtonClicked() {
	fd := walk.FileDialog{
		Filter:   "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
		FilePath: fmt.Sprintf("wireguard-log-%s.txt", time.Now().Format("2006-01-02T150405")),
		Title:    "Export log to file",
	}

	if ok, _ := fd.ShowSave(dlg); !ok {
		return
	}

	extensions := []string{".log", ".txt"}
	if fd.FilterIndex < 3 && !strings.HasSuffix(fd.FilePath, extensions[fd.FilterIndex-1]) {
		fd.FilePath = fd.FilePath + extensions[fd.FilterIndex-1]
	}

	writeFileWithOverwriteHandling(dlg, fd.FilePath, func(file *os.File) error {
		if _, err := dlg.logger.WriteTo(file); err != nil {
			return fmt.Errorf("exportLog: Ringlogger.WriteTo failed: %v", err)
		}

		return nil
	})
}

type logModel struct {
	walk.ReflectTableModelBase
	dlg    *LogDialog
	quit   chan bool
	logger *ringlogger.Ringlogger
	items  []ringlogger.FollowLine
}

func newLogModel(dlg *LogDialog, logger *ringlogger.Ringlogger) *logModel {
	mdl := &logModel{dlg: dlg, quit: make(chan bool), logger: logger}
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

					mdl.dlg.Synchronize(func() {
						isAtBottom := mdl.dlg.isAtBottom()

						mdl.items = items
						mdl.PublishRowsReset()

						if isAtBottom {
							mdl.dlg.scrollToBottom()
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
