// +build generate
//go:generate go run gotext.go

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/text/message/pipeline"
)

func main() {
	langDirs, err := ioutil.ReadDir("locales")
	if err != nil {
		panic(err)
	}
	var langs []string
	for _, dir := range langDirs {
		if !dir.IsDir() {
			continue
		}
		lang := dir.Name()
		if jsonData, err := ioutil.ReadFile(filepath.Join("locales", lang, "messages.gotext.json")); err == nil {
			var translations pipeline.Messages
			if err := json.Unmarshal(jsonData, &translations); err != nil {
				panic(err)
			}
			lang = translations.Language.String()
			if lang != dir.Name() {
				err = os.Rename(filepath.Join("locales", dir.Name()), filepath.Join("locales", lang))
				if err != nil {
					panic(err)
				}
			}
		} else if os.IsNotExist(err) {
			panic(err)
		}
		langs = append(langs, lang)
	}
	if len(langs) == 0 {
		panic("no locales found")
	}
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
	cmd = exec.Command(gotextFilename, "-srclang=en", "update", "-out=zgotext.go", "-lang="+strings.Join(langs, ","))
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(err)
	}
}
