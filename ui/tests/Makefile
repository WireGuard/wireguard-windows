export CFLAGS := -O3 -Wall -std=gnu11
export CC := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres
export CGO_ENABLED := 1
export GOOS := windows
export GOARCH := amd64

DEPLOYMENT_HOST ?= winvm
DEPLOYMENT_PATH ?= Desktop

all: tests.exe

resources.syso: ../../resources.rc ../../manifest.xml ../icon/icon.ico
	$(WINDRES) -i $< -o $@ -O coff

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
tests.exe: resources.syso $(call rwildcard,..,*.go *.c *.h)
	go build -ldflags="-s -w" -v -o $@

deploy: tests.exe
	-ssh $(DEPLOYMENT_HOST) -- 'taskkill /im tests.exe /f'
	scp tests.exe $(DEPLOYMENT_HOST):$(DEPLOYMENT_PATH)

run: tests.exe
	wine tests.exe

clean:
	rm -rf resources.syso tests.exe

.PHONY: deploy run clean all
