// +build generate
//go:generate go run gotext.go -srclang=en update -out=zgotext.go -lang=en,fr,ja,sl

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"io/ioutil"
	"os"
	"os/exec"
)

func main() {
	gotext, err := ioutil.TempFile("", "gotext*.exe")
	if err != nil {
		panic(err)
	}
	gotextFilename := gotext.Name()
	gotext.Close()
	defer os.Remove(gotextFilename)
	cmd := exec.Command("go", "build", "-o", gotextFilename, "golang.org/x/text/cmd/gotext")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(err)
	}
	cmd = exec.Command(gotextFilename, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=1", "CC=x86_64-w64-mingw32-gcc")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(err)
	}
}
