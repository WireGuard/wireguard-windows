/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestThreads(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		rl, err := NewRinglogger("ringlogger_test.bin", "ONE")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 1024; i++ {
			fmt.Fprintf(rl, "bla bla bla %d", i)
		}
		rl.Close()
		wg.Done()
	}()
	go func() {
		rl, err := NewRinglogger("ringlogger_test.bin", "TWO")
		if err != nil {
			t.Fatal(err)
		}
		for i := 1024; i < 2047; i++ {
			fmt.Fprintf(rl, "bla bla bla %d", i)
		}
		rl.Close()
		wg.Done()
	}()
	wg.Wait()
}

func TestWriteText(t *testing.T) {
	rl, err := NewRinglogger("ringlogger_test.bin", "TXT")
	if err != nil {
		t.Fatal(err)
	}
	if len(os.Args) != 3 {
		t.Fatal("Should pass exactly one argument")
	}
	fmt.Fprintf(rl, os.Args[2])
	rl.Close()
}

func TestDump(t *testing.T) {
	rl, err := NewRinglogger("ringlogger_test.bin", "DMP")
	if err != nil {
		t.Fatal(err)
	}
	_, err = rl.WriteTo(os.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	rl.Close()
}

func TestFollow(t *testing.T) {
	rl, err := NewRinglogger("ringlogger_test.bin", "FOL")
	if err != nil {
		t.Fatal(err)
	}
	cursor := CursorAll
	for {
		var lines []FollowLine
		lines, cursor = rl.FollowFromCursor(cursor)
		for _, line := range lines {
			fmt.Printf("%v: %s\n", line.Stamp, line.Line)
		}
		time.Sleep(300 * time.Millisecond)
	}
}
