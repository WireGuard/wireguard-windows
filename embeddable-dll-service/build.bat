@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019 WireGuard LLC. All Rights Reserved.

setlocal
set BUILDDIR=%~dp0
set PATH=%BUILDDIR%..\.deps\go\bin;%BUILDDIR%..\.deps;%PATH%
set PATHEXT=.exe
cd /d %BUILDDIR% || exit /b 1

if exist ..\.deps\prepared goto :build
:installdeps
	call ..\build.bat || goto :error

:build
	set GOOS=windows
	set GOPATH=%BUILDDIR%..\.deps\gopath
	set GOROOT=%BUILDDIR%..\.deps\go
	set CGO_ENABLED=1
	set CGO_CFLAGS=-O3 -Wall -Wno-unused-function -Wno-switch -std=gnu11 -DWINVER=0x0601
	set CGO_LDFLAGS=-Wl,--dynamicbase -Wl,--nxcompat -Wl,--export-all-symbols
	call :build_plat x86 i686 386 || goto :error
	set CGO_LDFLAGS=%CGO_LDFLAGS% -Wl,--high-entropy-va
	call :build_plat amd64 x86_64 amd64 || goto :error

:success
	echo [+] Success
	exit /b 0

:build_plat
	set PATH=%BUILDDIR%..\.deps\%~2-w64-mingw32-native\bin;%PATH%
	set CC=%~2-w64-mingw32-gcc
	set GOARCH=%~3
	mkdir %1 >NUL 2>&1
	echo [+] Building library %1
	go build -buildmode c-shared -ldflags="-w -s" -trimpath -v -o "%~1/tunnel.dll" || exit /b 1
	del "%~1\tunnel.h"
	goto :eof

:error
	echo [-] Failed with error #%errorlevel%.
	cmd /c exit %errorlevel%
