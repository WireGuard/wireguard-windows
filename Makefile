export CFLAGS := -O3 -Wall -std=gnu11
GOFLAGS := -ldflags="-H windowsgui -s -w" -v
WINDRES := x86_64-w64-mingw32-windres
export CGO_ENABLED := 1
export GOOS := windows
OLD_GOROOT := $(GOROOT)
export GOROOT := $(PWD)/.deps/goroot

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
SOURCE_FILES := $(call rwildcard,,*.go *.c *.h) .deps/prepared
RESOURCE_FILES := resources.rc version.h manifest.xml ui/icon/icon.ico

DEPLOYMENT_HOST ?= winvm
DEPLOYMENT_PATH ?= Desktop

all: amd64/wireguard.exe x86/wireguard.exe

.deps/prepared: export GOROOT := $(OLD_GOROOT)
.deps/prepared: $(wildcard golang-*.patch)
	rm -rf .deps && mkdir -p .deps
	rsync --exclude=pkg/obj/go-build/trim.txt -aq $$(go env GOROOT)/ .deps/goroot
	cat $^ | patch -f -N -r- -p1 -d .deps/goroot
	touch $@

resources_amd64.syso: $(RESOURCE_FILES)
	x86_64-w64-mingw32-windres -i $< -o $@ -O coff

resources_386.syso: $(RESOURCE_FILES)
	i686-w64-mingw32-windres -i $< -o $@ -O coff

amd64/wireguard.exe: export CC := x86_64-w64-mingw32-gcc
amd64/wireguard.exe: export GOARCH := amd64
amd64/wireguard.exe: resources_amd64.syso $(SOURCE_FILES)
	go build $(GOFLAGS) -o $@

x86/wireguard.exe: export CC := i686-w64-mingw32-gcc
x86/wireguard.exe: export GOARCH := 386
x86/wireguard.exe: resources_386.syso $(SOURCE_FILES)
	go build $(GOFLAGS) -o $@

deploy: amd64/wireguard.exe
	-ssh $(DEPLOYMENT_HOST) -- 'taskkill /im wireguard.exe /f'
	scp $< $(DEPLOYMENT_HOST):$(DEPLOYMENT_PATH)

clean:
	rm -rf *.syso x86/ amd64/ .deps

.PHONY: deploy clean all
