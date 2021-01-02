@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.

setlocal
set BUILDDIR=%~dp0
set PATH=%BUILDDIR%..\.deps\go\bin;%BUILDDIR%..\.deps;%PATH%
set PATHEXT=.exe
cd /d %BUILDDIR% || exit /b 1

if exist .prepared goto :build
:installdeps
	call ..\build.bat || goto :error
	pushd ..\.deps || goto :error
	rem Mirror of https://musl.cc/i686-w64-mingw32-native.zip
	call :download mingw-x86.zip https://download.wireguard.com/windows-toolchain/distfiles/i686-w64-mingw32-native-20200907.zip c972c00993727ac9bff83c799f4df65662adb95bc871fa30cfa8857e744a7fbd || goto :error
	rem Mirror of https://musl.cc/x86_64-w64-mingw32-native.zip
	call :download mingw-amd64.zip https://download.wireguard.com/windows-toolchain/distfiles/x86_64-w64-mingw32-native-20200907.zip e34fbacbd25b007a8074fc96f7e08f886241e0473a055987ee57483c37567aa5 || goto :error
	popd || goto :error
	copy /y NUL .prepared > NUL || goto :error

:build
	set GOOS=windows
	set GOPATH=%BUILDDIR%..\.deps\gopath
	set GOROOT=%BUILDDIR%..\.deps\go
	set CGO_ENABLED=1
	set CGO_CFLAGS=-O3 -Wall -Wno-unused-function -Wno-switch -std=gnu11 -DWINVER=0x0601
	call :build_plat x86 i686 386 || goto :error
	call :build_plat amd64 x86_64 amd64 || goto :error

:success
	echo [+] Success
	exit /b 0

:download
	echo [+] Downloading %1
	curl -#fLo %1 %2 || exit /b 1
	echo [+] Verifying %1
	for /f %%a in ('CertUtil -hashfile %1 SHA256 ^| findstr /r "^[0-9a-f]*$"') do if not "%%a"=="%~3" exit /b 1
	echo [+] Extracting %1
	tar -xf %1 %~4 || exit /b 1
	echo [+] Cleaning up %1
	del %1 || exit /b 1
	goto :eof

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
