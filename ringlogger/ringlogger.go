/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	maxLogLineLength = 512
	maxLines         = 2048
	magic            = 0xbadbabe
)

type logLine struct {
	timeNs int64
	line   [maxLogLineLength]byte
}

type logMem struct {
	magic     uint32
	nextIndex uint32
	lines     [maxLines]logLine
}

type Ringlogger struct {
	tag      string
	file     *os.File
	mapping  windows.Handle
	log      *logMem
	readOnly bool
}

func NewRinglogger(filename string, tag string) (*Ringlogger, error) {
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	err = file.Truncate(int64(unsafe.Sizeof(logMem{})))
	if err != nil {
		return nil, err
	}
	mapping, err := windows.CreateFileMapping(windows.Handle(file.Fd()), nil, windows.PAGE_READWRITE, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	rl, err := newRingloggerFromMappingHandle(mapping, tag, windows.FILE_MAP_WRITE)
	if err != nil {
		return nil, err
	}
	rl.file = file
	return rl, nil
}

func NewRingloggerFromInheritedMappingHandle(handleStr string, tag string) (*Ringlogger, error) {
	handle, err := strconv.ParseUint(handleStr, 10, 64)
	if err != nil {
		return nil, err
	}
	return newRingloggerFromMappingHandle(windows.Handle(handle), tag, windows.FILE_MAP_READ)
}

func newRingloggerFromMappingHandle(mappingHandle windows.Handle, tag string, access uint32) (*Ringlogger, error) {
	view, err := windows.MapViewOfFile(mappingHandle, access, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	if err != nil {
		windows.CloseHandle(mappingHandle)
		return nil, err
	}
	log := (*logMem)(unsafe.Pointer(view))
	if log.magic != magic {
		bytes := (*[unsafe.Sizeof(logMem{})]byte)(unsafe.Pointer(log))
		for i := range bytes {
			bytes[i] = 0
		}
		log.magic = magic
		windows.FlushViewOfFile(view, uintptr(len(bytes)))
	}

	rl := &Ringlogger{
		tag:      tag,
		mapping:  mappingHandle,
		log:      log,
		readOnly: access&windows.FILE_MAP_WRITE == 0,
	}
	runtime.SetFinalizer(rl, (*Ringlogger).Close)
	return rl, nil
}

func (rl *Ringlogger) Write(p []byte) (n int, err error) {
	if rl.readOnly {
		return 0, io.ErrShortWrite
	}

	// Race: This isn't synchronized with the fetch_add below, so items might be slightly out of order.
	ts := time.Now().UnixNano()

	if rl.log == nil {
		return 0, io.EOF
	}

	// Race: More than maxLines writers and this will clash.
	index := atomic.AddUint32(&rl.log.nextIndex, 1) - 1
	line := &rl.log.lines[index%maxLines]

	// Race: Before this line executes, we'll display old data after new data.
	atomic.StoreInt64(&line.timeNs, 0)
	for i := range line.line {
		line.line[i] = 0
	}

	text := []byte(fmt.Sprintf("[%s] %s", rl.tag, bytes.TrimSpace(p)))
	if len(text) > maxLogLineLength-1 {
		text = text[:maxLogLineLength-1]
	}
	line.line[len(text)] = 0
	copy(line.line[:], text[:])
	atomic.StoreInt64(&line.timeNs, ts)

	windows.FlushViewOfFile((uintptr)(unsafe.Pointer(&rl.log.nextIndex)), unsafe.Sizeof(rl.log.nextIndex))
	windows.FlushViewOfFile((uintptr)(unsafe.Pointer(line)), unsafe.Sizeof(*line))

	return len(p), nil
}

func (rl *Ringlogger) WriteTo(out io.Writer) (n int64, err error) {
	if rl.log == nil {
		return 0, io.EOF
	}
	log := *rl.log
	i := log.nextIndex
	for l := 0; l < maxLines; l++ {
		line := &log.lines[i%maxLines]
		if line.timeNs == 0 {
			i++
			continue
		}
		index := bytes.IndexByte(line.line[:], 0)
		if index < 1 {
			i++
			continue
		}
		var bytes int
		bytes, err = fmt.Fprintf(out, "%s: %s\n", time.Unix(0, line.timeNs).Format("2006-01-02 15:04:05.000000"), line.line[:index])
		if err != nil {
			return
		}
		n += int64(bytes)
		i++
	}
	return
}

const CursorAll = ^uint32(0)

type FollowLine struct {
	Line  string
	Stamp time.Time
}

func (rl *Ringlogger) FollowFromCursor(cursor uint32) (followLines []FollowLine, nextCursor uint32) {
	followLines = make([]FollowLine, 0, maxLines)
	nextCursor = cursor

	if rl.log == nil {
		return
	}
	log := *rl.log

	i := cursor
	if cursor == CursorAll {
		i = log.nextIndex
	}

	for l := 0; l < maxLines; l++ {
		line := &log.lines[i%maxLines]
		if cursor != CursorAll && i%maxLines == log.nextIndex%maxLines {
			break
		}
		if line.timeNs == 0 {
			if cursor == CursorAll {
				i++
				continue
			} else {
				break
			}
		}
		index := bytes.IndexByte(line.line[:], 0)
		if index > 0 {
			followLines = append(followLines, FollowLine{string(line.line[:index]), time.Unix(0, line.timeNs)})
		}
		i++
		nextCursor = i % maxLines
	}
	return
}

func (rl *Ringlogger) Close() error {
	if rl.file != nil {
		rl.file.Close()
		rl.file = nil
	}
	if rl.log != nil {
		windows.UnmapViewOfFile((uintptr)(unsafe.Pointer(rl.log)))
		rl.log = nil
	}
	if rl.mapping != 0 {
		windows.CloseHandle(rl.mapping)
		rl.mapping = 0
	}
	return nil
}

func (rl *Ringlogger) ExportInheritableMappingHandleStr() (str string, handleToClose windows.Handle, err error) {
	handleToClose, err = windows.CreateFileMapping(windows.Handle(rl.file.Fd()), nil, windows.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return
	}
	err = windows.SetHandleInformation(handleToClose, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT)
	if err != nil {
		windows.Close(handleToClose)
		handleToClose = 0
		return
	}
	str = strconv.FormatUint(uint64(handleToClose), 10)
	return
}
