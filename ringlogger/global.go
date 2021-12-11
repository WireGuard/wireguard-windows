/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"log"
	"unsafe"
)

var Global *Ringlogger

func InitGlobalLogger(file, tag string) error {
	if Global != nil {
		return nil
	}
	var err error
	Global, err = NewRinglogger(file, tag)
	if err != nil {
		return err
	}
	log.SetOutput(Global)
	log.SetFlags(0)
	overrideWrite = globalWrite
	return nil
}

//go:linkname overrideWrite runtime.overrideWrite
var overrideWrite func(fd uintptr, p unsafe.Pointer, n int32) int32

var (
	globalBuffer         [maxLogLineLength - 1 - maxTagLength - 3]byte
	globalBufferLocation int
)

//go:nosplit
func globalWrite(fd uintptr, p unsafe.Pointer, n int32) int32 {
	b := (*[1 << 30]byte)(p)[:n]
	for len(b) > 0 {
		amountAvailable := len(globalBuffer) - globalBufferLocation
		amountToCopy := len(b)
		if amountToCopy > amountAvailable {
			amountToCopy = amountAvailable
		}
		copy(globalBuffer[globalBufferLocation:], b[:amountToCopy])
		b = b[amountToCopy:]
		globalBufferLocation += amountToCopy
		foundNl := false
		for i := globalBufferLocation - amountToCopy; i < globalBufferLocation; i++ {
			if globalBuffer[i] == '\n' {
				foundNl = true
				break
			}
		}
		if foundNl || len(b) > 0 {
			Global.Write(globalBuffer[:globalBufferLocation])
			globalBufferLocation = 0
		}
	}
	return n
}
