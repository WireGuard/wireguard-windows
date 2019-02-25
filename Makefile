CFLAGS ?= -O3
CFLAGS += -Wall -std=gnu11
export CGO_ENABLED := 1
export CGO_CFLAGS := $(CFLAGS)
export CC := x86_64-w64-mingw32-gcc
export GOOS := windows
export GOARCH := amd64
export PATH := $(PATH):$(GOPATH)/bin

all: wireguard.exe

BUILDDIR := .tmp
rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
DOWNSTREAM_FILES := $(filter-out %/.tmp wireguard-go/%,$(call rwildcard,,*.go *.c *.h)) go.mod
UPSTREAM_FILES := $(filter-out $(addprefix %/,$(DOWNSTREAM_FILES)) %/.tmp %/main_windows.go,$(call rwildcard,wireguard-go/,*.go))

define copy-src-to-build
$(BUILDDIR)/$(3)/$(patsubst $(1)%,%,$(2)): $(2)
	@mkdir -vp "$$(dir $$@)"
	@cp -vp "$$<" "$$@"
	@$$(if $(3),sed -i 's:golang.zx2c4.com/wireguard:golang.zx2c4.com/wireguard/windows/$(3):;s:package main:package $(3):' "$$@",)
$(BUILDDIR)/.prepared: $(BUILDDIR)/$(3)/$(patsubst $(1)%,%,$(2))
endef

$(foreach FILE,$(UPSTREAM_FILES),$(eval $(call copy-src-to-build,wireguard-go/,$(FILE),service)))
$(foreach FILE,$(DOWNSTREAM_FILES),$(eval $(call copy-src-to-build,,$(FILE))))

$(BUILDDIR)/.prepared:
	touch "$@"

$(BUILDDIR)/resources.syso: ui/icon/icon.ico ui/manifest.xml
	rsrc -manifest ui/manifest.xml -ico ui/icon/icon.ico -arch amd64 -o $@

wireguard.exe: $(BUILDDIR)/.prepared $(BUILDDIR)/resources.syso
	cd "$(BUILDDIR)" && go build -ldflags="-H windowsgui" -o ../$@ -v

run: wireguard.exe
	wine wireguard.exe

clean:
	rm -rf "$(BUILDDIR)" wireguard.exe

.PHONY: run clean all
