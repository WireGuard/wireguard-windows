export CFLAGS := -O3 -Wall -std=gnu11
export CC := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres
export CGO_ENABLED := 1
export GOOS := windows
export GOARCH := amd64

DEPLOYMENT_HOST ?= winvm
DEPLOYMENT_PATH ?= Desktop

all: wireguard.exe

resources.syso: resources.rc manifest.xml ui/icon/icon.ico
	$(WINDRES) -i $< -o $@ -O coff

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
wireguard.exe: resources.syso $(call rwildcard,,*.go *.c *.h)
	go build -ldflags="-H windowsgui -s -w" -v -o $@

deploy: wireguard.exe
	-ssh $(DEPLOYMENT_HOST) -- 'taskkill /im wireguard.exe /f'
	scp wireguard.exe $(DEPLOYMENT_HOST):$(DEPLOYMENT_PATH)

clean:
	rm -rf resources.syso wireguard.exe

.PHONY: deploy clean all
