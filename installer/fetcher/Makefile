# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

CFLAGS ?= -Os
DEPLOYMENT_HOST ?= winvm
DEPLOYMENT_PATH ?= Desktop

CFLAGS += -std=gnu11 -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -flto
CFLAGS += -Wall -Wextra
CFLAGS += -MMD -MP
LDLIBS += -lkernel32 -lwinhttp -lntdll -lshlwapi -lmsi -lcomctl32 -luser32 -lshell32 -lwintrust -lbcrypt
LDFLAGS += -s -flto -Wl,--dynamicbase -Wl,--nxcompat -Wl,--tsaware -mwindows
LDFLAGS += -Wl,--major-os-version=6 -Wl,--minor-os-version=1 -Wl,--major-subsystem-version=6 -Wl,--minor-subsystem-version=1
# The use of -Wl,/delayload: here implies we're using llvm-mingw
LDFLAGS += -Wl,/delayload:winhttp.dll -Wl,/delayload:msi.dll -Wl,/delayload:wintrust.dll -Wl,/delayload:advapi32.dll -Wl,/delayload:shell32.dll -Wl,/delayload:shlwapi.dll -Wl,/delayload:gdi32.dll -Wl,/delayload:user32.dll -Wl,/delayload:comctl32.dll -Wl,/delayload:bcrypt.dll
TARGET := wireguard-installer.exe
CC := i686-w64-mingw32-clang
WINDRES := i686-w64-mingw32-windres

$(TARGET): $(sort $(patsubst %.c,%.o,$(wildcard *.c))) resources.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

%.ico: %.svg
	convert -background none $< -define icon:auto-resize="64,32,16" -compress zip $@

resources.o: resources.rc icon.ico manifest.xml
	$(WINDRES) -O coff -c 65001 -i $< -o $@

clean:
	$(RM) $(TARGET) *.o *.d *.ico

deploy: $(TARGET)
	scp $< $(DEPLOYMENT_HOST):$(DEPLOYMENT_PATH)

sign: deploy
	ssh $(DEPLOYMENT_HOST) '"C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe"' sign /sha1 $(SIGNING_CERTIFICATE) /fd sha256 /tr $(TIMESTAMP_SERVER) /td sha256 /d '"WireGuard Installer"' '$(DEPLOYMENT_PATH)\$(TARGET)'
	scp -T '$(DEPLOYMENT_HOST):$(DEPLOYMENT_PATH)\$(TARGET)' .

.PHONY: clean deploy sign

-include *.d
