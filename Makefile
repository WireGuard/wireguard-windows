CFLAGS ?= -O3
CFLAGS += -Wall -std=gnu11

all: wireguard.exe

resources.syso: ui/icon/icon.ico ui/manifest.xml go.mod
	go run github.com/akavel/rsrc -manifest ui/manifest.xml -ico ui/icon/icon.ico -arch amd64 -o resources.syso

wireguard.exe: resources.syso
	CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -ldflags="-H windowsgui" -o $@

run: wireguard.exe
	wine wireguard.exe

clean:
	rm -rf resources.syso wireguard.exe

.PHONY: run clean all
