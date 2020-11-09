GOFLAGS := -ldflags="-H windowsgui -s -w" -v -trimpath
export GOOS := windows
export PATH := $(CURDIR)/.deps/go/bin:$(PATH)

VERSION := $(shell sed -n 's/^\s*Number\s*=\s*"\([0-9.]\+\)"$$/\1/p' version/version.go)
empty :=
space := $(empty) $(empty)
comma := ,
RCFLAGS := -DWIREGUARD_VERSION_ARRAY=$(subst $(space),$(comma),$(wordlist 1,4,$(subst .,$(space),$(VERSION)) 0 0 0 0)) -DWIREGUARD_VERSION_STR=$(VERSION) -O coff -c 65001

rwildcard=$(foreach d,$(filter-out .deps,$(wildcard $1*)),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
SOURCE_FILES := $(call rwildcard,,*.go) .deps/go/prepared go.mod go.sum
RESOURCE_FILES := resources.rc version/version.go manifest.xml $(patsubst %.svg,%.ico,$(wildcard ui/icon/*.svg)) .deps/wintun/prepared

DEPLOYMENT_HOST ?= winvm
DEPLOYMENT_PATH ?= Desktop

all: amd64/wireguard.exe x86/wireguard.exe arm64/wireguard.exe arm/wireguard.exe

define download =
.distfiles/$(1):
	mkdir -p .distfiles
	if ! curl -L#o $$@.unverified $(2); then rm -f $$@.unverified; exit 1; fi
	if ! echo "$(3)  $$@.unverified" | sha256sum -c; then rm -f $$@.unverified; exit 1; fi
	if ! mv $$@.unverified $$@; then rm -f $$@.unverified; exit 1; fi
endef

$(eval $(call download,go.tar.gz,https://golang.org/dl/go1.15.4.linux-amd64.tar.gz,eb61005f0b932c93b424a3a4eaa67d72196c79129d9a3ea8578047683e2c80d5))
$(eval $(call download,wintun.zip,https://www.wintun.net/builds/wintun-0.9.zip,ef435b3c26fdb3bd79dd3f27f4e0020af1733e6cd186c93072dd540a13fcd53e))

.deps/go/prepared: .distfiles/go.tar.gz $(wildcard go-patches/*.patch)
	mkdir -p .deps
	tar -C .deps -xzf .distfiles/go.tar.gz
	chmod -R +w .deps/go
	cat $(filter %.patch,$^) | patch -f -N -r- -p1 -d .deps/go
	cd .deps/go/src && GOOS=linux go build -v -o ../pkg/tool/linux_amd64/link cmd/link
	touch $@

.deps/wintun/prepared: .distfiles/wintun.zip
	mkdir -p .deps
	bsdtar -C .deps -xf .distfiles/wintun.zip
	touch $@

%.ico: %.svg
	convert -background none $< -define icon:auto-resize="256,192,128,96,64,48,32,24,16" $@

resources_amd64.syso: $(RESOURCE_FILES)
	x86_64-w64-mingw32-windres $(RCFLAGS) -I .deps/wintun/bin/amd64 -i $< -o $@

resources_386.syso: $(RESOURCE_FILES)
	i686-w64-mingw32-windres $(RCFLAGS) -I .deps/wintun/bin/x86 -i $< -o $@

resources_arm.syso: $(RESOURCE_FILES)
	armv7-w64-mingw32-windres $(RCFLAGS) -I .deps/wintun/bin/arm -i $< -o $@

amd64/wireguard.exe: export GOARCH := amd64
amd64/wireguard.exe: resources_amd64.syso $(SOURCE_FILES)
	go build $(GOFLAGS) -o $@

x86/wireguard.exe: export GOARCH := 386
x86/wireguard.exe: resources_386.syso $(SOURCE_FILES)
	go build $(GOFLAGS) -o $@

arm/wireguard.exe: export GOARCH := arm
arm/wireguard.exe: export GOARM := 7
arm/wireguard.exe: resources_arm.syso $(SOURCE_FILES)
	go build $(GOFLAGS) -o $@

arm64/wireguard.exe: arm/wireguard.exe
	mkdir -p $(@D)
	cp $< $@

remaster: export GOARCH := amd64
remaster: export GOPROXY := direct
remaster: .deps/go/prepared
	rm -f go.sum go.mod
	cp go.mod.master go.mod
	go get -d

fmt: export GOARCH := amd64
fmt: .deps/go/prepared
	go fmt ./...

generate: export GOOS :=
generate: .deps/go/prepared
	go generate ./...

crowdin:
	find locales -maxdepth 1 -mindepth 1 -type d \! -name en -exec rm -rf {} +
	curl -Lo - https://crowdin.com/backend/download/project/wireguard.zip | bsdtar -C locales -x -f - --strip-components 2 wireguard-windows
	find locales -name messages.gotext.json -exec bash -c '[[ $$(jq ".messages | length" {}) -ne 0 ]] || rm -rf "$$(dirname {})"' \;
	@$(MAKE) --no-print-directory generate

deploy: amd64/wireguard.exe
	-ssh $(DEPLOYMENT_HOST) -- 'taskkill /im wireguard.exe /f'
	scp $< $(DEPLOYMENT_HOST):$(DEPLOYMENT_PATH)

clean:
	rm -rf *.syso ui/icon/*.ico x86/ amd64/ arm/ arm64/ .deps

distclean: clean
	rm -rf .distfiles

.PHONY: deploy clean distclean fmt remaster generate all
