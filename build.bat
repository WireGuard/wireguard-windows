@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019 WireGuard LLC. All Rights Reserved.

set STARTDIR=%cd%
set OLDPATH=%PATH%

if exist .deps\prepared goto :render
:installdeps
	rmdir /s /q .deps 2> NUL
	mkdir .deps || goto :error
	cd .deps || goto :error
	call :download go.zip https://dl.google.com/go/go1.12.3.windows-amd64.zip 1806e089e85b84f192d782a7f70f90a32e0eccfd181405857e612f806ec04059 || goto :error
	rem Mirror of https://musl.cc/i686-w64-mingw32-native.zip
	call :download mingw-x86.zip https://download.wireguard.com/windows-toolchain/distfiles/i686-w64-mingw32-native-20190425.zip 5810b4a9af34c12690ec355ad2a237d2a4c16f5e8cb68988dc0f2e48457534d0 || goto :error
	rem Mirror of https://musl.cc/x86_64-w64-mingw32-native.zip
	call :download mingw-amd64.zip https://download.wireguard.com/windows-toolchain/distfiles/x86_64-w64-mingw32-native-20190307.zip 5390762183e181804b28eb13815b6210f85a1280057b815f749b06768215f817 || goto :error
	rem Mirror of https://imagemagick.org/download/binaries/ImageMagick-7.0.8-42-portable-Q16-x64.zip
	call :download imagemagick.zip https://download.wireguard.com/windows-toolchain/distfiles/ImageMagick-7.0.8-42-portable-Q16-x64.zip 584e069f56456ce7dde40220948ff9568ac810688c892c5dfb7f6db902aa05aa "convert.exe colors.xml delegates.xml" || goto :error
	rem Mirror of https://sourceforge.net/projects/gnuwin32/files/patch/2.5.9-7/patch-2.5.9-7-bin.zip with fixed manifest
	call :download patch.zip https://download.wireguard.com/windows-toolchain/distfiles/patch-2.5.9-7-bin-fixed-manifest.zip 25977006ca9713f2662a5d0a2ed3a5a138225b8be3757035bd7da9dcf985d0a1 "--strip-components 1 bin" || goto :error
	echo [+] Patching go
	for %%a in ("..\golang-*.patch") do .\patch.exe -f -N -r- -d go -p1 --binary < "%%a" || goto :error
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error

:render
	echo [+] Rendering icons
	for %%a in ("ui\icon\*.svg") do "%STARTDIR%\.deps\convert.exe" -background none "%%~fa" -define icon:auto-resize="256,128,96,64,48,32,16" "%%~dpna.ico" || goto :error

:build
	set PATH=%STARTDIR%\.deps\go\bin\;%PATH%
	set GOOS=windows
	set GOPATH=%STARTDIR%\.deps\gopath
	set GOROOT=%STARTDIR%\.deps\go
	set CGO_ENABLED=1
	set CGO_CFLAGS=-O3 -Wall -Wno-switch -std=gnu11 -DWINVER=0x0601
	call :build_plat x86 i686 386 || goto :error
	call :build_plat amd64 x86_64 amd64 || goto :error

:sign
	if exist .\sign.bat call .\sign.bat
	if "%SigningCertificate%"=="" goto :success
	if "%TimestampServer%"=="" goto :success
	echo [+] Signing
	signtool.exe sign /sha1 "%SigningCertificate%" /fd sha256 /tr "%TimestampServer%" /td sha256 /d WireGuard x86\wireguard.exe amd64\wireguard.exe || goto :error

:success
	echo [+] Success. Launch wireguard.exe.

:out
	set PATH=%OLDPATH%
	cd %STARTDIR%
	exit /b %errorlevel%

:error
	echo [-] Failed with error #%errorlevel%.
	goto :out

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
	set OLDPATH2=%PATH%
	set PATH=%STARTDIR%\.deps\%~2-w64-mingw32-native\bin;%PATH%
	set CC=%~2-w64-mingw32-gcc.exe
	set GOARCH=%~3
	mkdir %1 >NUL 2>&1
	echo [+] Assembling resources %1
	windres.exe -i resources.rc -o resources.syso -O coff || exit /b %errorlevel%
	echo [+] Building program %1
	go build -ldflags="-H windowsgui -s -w" -v -o "%~1\wireguard.exe" || exit /b 1
	set PATH=%OLDPATH2%
	goto :eof
