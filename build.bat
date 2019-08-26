@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019 WireGuard LLC. All Rights Reserved.

setlocal
set BUILDDIR=%~dp0
set PATH=%BUILDDIR%.deps\go\bin;%BUILDDIR%.deps;%PATH%
set PATHEXT=.exe
cd /d %BUILDDIR% || exit /b 1

if exist .deps\prepared goto :render
:installdeps
	rmdir /s /q .deps 2> NUL
	mkdir .deps || goto :error
	cd .deps || goto :error
	call :download go.zip https://dl.google.com/go/go1.13beta1.windows-amd64.zip 08098b4b0e1a105971d2fced2842e806f8ffa08973ae8781fd22dd90f76404fb || goto :error
	rem Mirror of https://musl.cc/i686-w64-mingw32-native.zip
	call :download mingw-x86.zip https://download.wireguard.com/windows-toolchain/distfiles/i686-w64-mingw32-native-20190602.zip 003b7d07c837bfd365cf282772fb478bfd83195ee7f755d789420a6a651553a9 || goto :error
	rem Mirror of https://musl.cc/x86_64-w64-mingw32-native.zip
	call :download mingw-amd64.zip https://download.wireguard.com/windows-toolchain/distfiles/x86_64-w64-mingw32-native-20190602.zip 5e6629630f106dcad132f8b4eefdb6d2f98b1db251a1cf48a9f654da68793dad || goto :error
	rem Mirror of https://imagemagick.org/download/binaries/ImageMagick-7.0.8-42-portable-Q16-x64.zip
	call :download imagemagick.zip https://download.wireguard.com/windows-toolchain/distfiles/ImageMagick-7.0.8-42-portable-Q16-x64.zip 584e069f56456ce7dde40220948ff9568ac810688c892c5dfb7f6db902aa05aa "convert.exe colors.xml delegates.xml" || goto :error
	rem Mirror of https://sourceforge.net/projects/ezwinports/files/make-4.2.1-without-guile-w32-bin.zip
	call :download make.zip https://download.wireguard.com/windows-toolchain/distfiles/make-4.2.1-without-guile-w32-bin.zip 30641be9602712be76212b99df7209f4f8f518ba764cf564262bc9d6e4047cc7 "--strip-components 1 bin" || goto :error
	call :download wireguard-tools.zip https://git.zx2c4.com/WireGuard/snapshot/WireGuard-0.0.20190702.zip 2fb45e145f36e4e965f8acb48061603a2192c6729266cbcd9f9669024e433588 "--exclude wg-quick --strip-components 1" || goto :error
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error

:render
	echo [+] Rendering icons
	for %%a in ("ui\icon\*.svg") do convert -background none "%%~fa" -define icon:auto-resize="256,128,96,64,48,32,16" "%%~dpna.ico" || goto :error

:build
	set GOOS=windows
	set GOPATH=%BUILDDIR%.deps\gopath
	set GOROOT=%BUILDDIR%.deps\go
	set CGO_ENABLED=1
	set CGO_CFLAGS=-O3 -Wall -Wno-unused-function -Wno-switch -std=gnu11 -DWINVER=0x0601
	set CGO_LDFLAGS=-Wl,--major-os-version=6 -Wl,--minor-os-version=1 -Wl,--major-subsystem-version=6 -Wl,--minor-subsystem-version=1
	call :build_plat x86 i686 386 || goto :error
	call :build_plat amd64 x86_64 amd64 || goto :error

:sign
	if exist .\sign.bat call .\sign.bat
	if "%SigningCertificate%"=="" goto :success
	if "%TimestampServer%"=="" goto :success
	echo [+] Signing
	signtool sign /sha1 "%SigningCertificate%" /fd sha256 /tr "%TimestampServer%" /td sha256 /d WireGuard x86\wireguard.exe x86\wg.exe amd64\wireguard.exe amd64\wg.exe || goto :error

:success
	echo [+] Success. Launch wireguard.exe.
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
	set PATH=%BUILDDIR%.deps\%~2-w64-mingw32-native\bin;%PATH%
	set CC=%~2-w64-mingw32-gcc
	set GOARCH=%~3
	mkdir %1 >NUL 2>&1
	echo [+] Assembling resources %1
	windres -i resources.rc -o resources.syso -O coff || exit /b %errorlevel%
	echo [+] Building program %1
	go build -ldflags="-H windowsgui -s -w" -tags walk_use_cgo -trimpath -v -o "%~1\wireguard.exe" || exit /b 1
	if not exist "%~1\wg.exe" (
		echo [+] Building command line tools %1
		del .deps\src\tools\*.exe .deps\src\tools\*.o .deps\src\tools\wincompat\*.o 2> NUL
		make --no-print-directory -C .deps\src\tools PLATFORM=windows CC=%CC% V=1 LDFLAGS=-s RUNSTATEDIR= SYSTEMDUNITDIR= -j%NUMBER_OF_PROCESSORS% || exit /b 1
		move /Y .deps\src\tools\wg.exe "%~1\wg.exe" > NUL || exit /b 1
	)
	goto :eof

:error
	echo [-] Failed with error #%errorlevel%.
	cmd /c exit %errorlevel%
