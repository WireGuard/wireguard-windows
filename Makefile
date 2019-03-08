export CFLAGS := -O3 -Wall -std=gnu11
export CC := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres
export CGO_ENABLED := 1
export GOOS := windows
export GOARCH := amd64
REAL_GOROOT := $(shell go env GOROOT)
export GOROOT := $(PWD)/deps/go
export PATH := $(GOROOT)/bin:$(PATH)

DEPLOYMENT_HOST ?= winvm
DEPLOYMENT_PATH ?= Desktop

all: wireguard.exe

deps/.prepared:
	mkdir -p deps
	rsync -a --delete --exclude=pkg/obj/go-build "$(REAL_GOROOT)/" "$(GOROOT)/"
	patch -f -N -r- -d deps/go -p1 < golang-runtime-dll-injection.patch
	touch "$@"

resources.syso: resources.rc manifest.xml ui/icon/icon.ico
	$(WINDRES) -i $< -o $@ -O coff

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
wireguard.exe: resources.syso $(call rwildcard,,*.go *.c *.h) deps/.prepared
	go build -ldflags="-H windowsgui -s -w" -v -o $@

deploy: wireguard.exe
	-ssh $(DEPLOYMENT_HOST) -- 'taskkill /im wireguard.exe /f'
	scp wireguard.exe $(DEPLOYMENT_HOST):$(DEPLOYMENT_PATH)

clean:
	rm -rf resources.syso wireguard.exe deps

.PHONY: deploy clean all
