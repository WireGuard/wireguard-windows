/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"golang.org/x/sys/windows"
	"os"
	"strconv"
)

type pipeRWC struct {
	reader *os.File
	writer *os.File
}

func (p *pipeRWC) Read(b []byte) (int, error) {
	return p.reader.Read(b)
}

func (p *pipeRWC) Write(b []byte) (int, error) {
	return p.writer.Write(b)
}

func (p *pipeRWC) Close() error {
	err1 := p.writer.Close()
	err2 := p.reader.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func inheritableSocketpairEmulation() (ourReader *os.File, theirReader *os.File, theirReaderStr string, ourWriter *os.File, theirWriter *os.File, theirWriterStr string, err error) {
	ourReader, theirWriter, err = os.Pipe()
	if err != nil {
		return
	}
	err = windows.SetHandleInformation(windows.Handle(theirWriter.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT)
	if err != nil {
		return
	}
	theirWriterStr = strconv.FormatUint(uint64(theirWriter.Fd()), 10)

	theirReader, ourWriter, err = os.Pipe()
	if err != nil {
		return
	}
	err = windows.SetHandleInformation(windows.Handle(theirReader.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT)
	if err != nil {
		return
	}
	theirReaderStr = strconv.FormatUint(uint64(theirReader.Fd()), 10)

	return
}
