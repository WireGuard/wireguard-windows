/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"os"
	"strconv"

	"golang.org/x/sys/windows"
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

func makeInheritableAndGetStr(f *os.File) (str string, err error) {
	sc, err := f.SyscallConn()
	if err != nil {
		return
	}
	err2 := sc.Control(func(fd uintptr) {
		err = windows.SetHandleInformation(windows.Handle(fd), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT)
		str = strconv.FormatUint(uint64(fd), 10)
	})
	if err2 != nil {
		err = err2
	}
	return
}

func inheritableEvents() (ourEvents *os.File, theirEvents *os.File, theirEventStr string, err error) {
	theirEvents, ourEvents, err = os.Pipe()
	if err != nil {
		return
	}
	theirEventStr, err = makeInheritableAndGetStr(theirEvents)
	return
}

func inheritableSocketpairEmulation() (ourReader *os.File, theirReader *os.File, theirReaderStr string, ourWriter *os.File, theirWriter *os.File, theirWriterStr string, err error) {
	ourReader, theirWriter, err = os.Pipe()
	if err != nil {
		return
	}
	theirWriterStr, err = makeInheritableAndGetStr(theirWriter)
	if err != nil {
		return
	}

	theirReader, ourWriter, err = os.Pipe()
	if err != nil {
		return
	}
	theirReaderStr, err = makeInheritableAndGetStr(theirReader)
	return
}
