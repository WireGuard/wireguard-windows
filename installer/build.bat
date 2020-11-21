@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.

setlocal
set PATHEXT=.exe
set BUILDDIR=%~dp0
cd /d %BUILDDIR% || exit /b 1

for /f "tokens=3" %%a in ('findstr /r "Number.*=.*[0-9.]*" ..\version\version.go') do set WIREGUARD_VERSION=%%a
set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%

set WIX_CANDLE_FLAGS=-nologo -dWIREGUARD_VERSION="%WIREGUARD_VERSION%"
set WIX_LIGHT_FLAGS=-nologo -spdb
set WIX_LIGHT_FLAGS=%WIX_LIGHT_FLAGS% -sice:ICE39
set WIX_LIGHT_FLAGS=%WIX_LIGHT_FLAGS% -sice:ICE61
set WIX_LIGHT_FLAGS=%WIX_LIGHT_FLAGS% -sice:ICE03

if exist .deps\prepared goto :build
:installdeps
	rmdir /s /q .deps 2> NUL
	mkdir .deps || goto :error
	cd .deps || goto :error
	call :download wix-binaries.zip https://wixtoolset.org/downloads/v3.14.0.4118/wix314-binaries.zip 34dcbba9952902bfb710161bd45ee2e721ffa878db99f738285a21c9b09c6edb || goto :error
	echo [+] Extracting wix-binaries.zip
	mkdir wix\bin || goto :error
	tar -xf wix-binaries.zip -C wix\bin || goto :error
	echo [+] Cleaning up wix-binaries.zip
	del wix-binaries.zip || goto :error
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error

:build
	set PATH=%BUILDDIR%..\.deps\llvm-mingw\bin;%PATH%
	set WIX=%BUILDDIR%.deps\wix\
	set CFLAGS=-O3 -Wall -std=gnu11 -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -municode -DUNICODE -D_UNICODE -DNDEBUG
	set LDFLAGS=-shared -s -Wl,--kill-at -Wl,--major-os-version=6 -Wl,--minor-os-version=1 -Wl,--major-subsystem-version=6 -Wl,--minor-subsystem-version=1 -Wl,--tsaware -Wl,--dynamicbase -Wl,--nxcompat -Wl,--export-all-symbols
	set LDLIBS=-lmsi -lole32 -lshlwapi -lshell32 -luuid -lntdll
	call :msi x86 i686 x86 || goto :error
	call :msi amd64 x86_64 x64 || goto :error
	call :msi arm armv7 arm || goto :error
	call :msi arm64 aarch64 arm64 || goto :error
	if exist ..\sign.bat call ..\sign.bat
	if "%SigningCertificate%"=="" goto :success
	if "%TimestampServer%"=="" goto :success
	echo [+] Signing
	signtool sign /sha1 "%SigningCertificate%" /fd sha256 /tr "%TimestampServer%" /td sha256 /d "WireGuard Setup" "dist\wireguard-*-%WIREGUARD_VERSION%.msi" || goto :error

:success
	echo [+] Success.
	exit /b 0

:download
	echo [+] Downloading %1
	curl -#fLo %1 %2 || exit /b 1
	echo [+] Verifying %1
	for /f %%a in ('CertUtil -hashfile %1 SHA256 ^| findstr /r "^[0-9a-f]*$"') do if not "%%a"=="%~3" exit /b 1
	goto :eof

:msi
	set CC=%~2-w64-mingw32-gcc
	if not exist "%~1" mkdir "%~1"
	echo [+] Compiling %1
	%CC% %CFLAGS% %LDFLAGS% -o "%~1\customactions.dll" customactions.c %LDLIBS% || exit /b 1
	"%WIX%bin\candle" %WIX_CANDLE_FLAGS% -dWIREGUARD_PLATFORM="%~1" -out "%~1\wireguard.wixobj" -arch %3 wireguard.wxs || exit /b %errorlevel%
	echo [+] Linking %1
	"%WIX%bin\light" %WIX_LIGHT_FLAGS% -out "dist\wireguard-%~1-%WIREGUARD_VERSION%.msi" "%~1\wireguard.wixobj" || exit /b %errorlevel%
	goto :eof

:error
	echo [-] Failed with error #%errorlevel%.
	cmd /c exit %errorlevel%
