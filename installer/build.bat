@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019 WireGuard LLC. All Rights Reserved.

setlocal
set PATHEXT=.exe
set BUILDDIR=%~dp0
cd /d %BUILDDIR% || exit /b 1

for /f "tokens=3" %%a in ('findstr /r "WIREGUARD_WINDOWS_VERSION_STRING.*[0-9.]*" ..\version\version.h') do set WIREGUARD_VERSION=%%a
set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%

set WIX_CANDLE_FLAGS=-nologo -dWIREGUARD_VERSION="%WIREGUARD_VERSION%"
set WIX_LIGHT_FLAGS=-nologo -spdb
set WIX_LIGHT_FLAGS=%WIX_LIGHT_FLAGS% -sw1056
set WIX_LIGHT_FLAGS=%WIX_LIGHT_FLAGS% -sice:ICE30
set WIX_LIGHT_FLAGS=%WIX_LIGHT_FLAGS% -sice:ICE61
set WIX_LIGHT_FLAGS=%WIX_LIGHT_FLAGS% -sice:ICE09

if exist .deps\prepared goto :build
:installdeps
	rmdir /s /q .deps 2> NUL
	mkdir .deps || goto :error
	cd .deps || goto :error
	call :download wintun-x86.msm https://www.wintun.net/builds/wintun-x86-0.7.msm bdc40a2314964759653cd0717983dd3fedfeb53e7e15f4ed8370e12964c04b43 || goto :error
	call :download wintun-amd64.msm https://www.wintun.net/builds/wintun-amd64-0.7.msm c87f9e0df51ac5c4fc8551f38c58b6fe6c43c06344451e3ed8939f05f4979c7d || goto :error
	call :download wix-binaries.zip https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311-binaries.zip 2c1888d5d1dba377fc7fa14444cf556963747ff9a0a289a3599cf09da03b9e2e || goto :error
	echo [+] Extracting wix-binaries.zip
	mkdir wix\bin || goto :error
	tar -xf wix-binaries.zip -C wix\bin || goto :error
	echo [+] Cleaning up wix-binaries.zip
	del wix-binaries.zip || goto :error
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error

:build
	set WIX=%BUILDDIR%.deps\wix\
	set CFLAGS=-O3 -Wall -std=gnu11 -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -municode -DUNICODE -D_UNICODE -DNDEBUG
	set LDFLAGS=-shared -s -Wl,--kill-at -Wl,--major-os-version=6 -Wl,--minor-os-version=1 -Wl,--major-subsystem-version=6 -Wl,--minor-subsystem-version=1 -Wl,--tsaware -Wl,--dynamicbase -Wl,--nxcompat -Wl,--export-all-symbols
	set LDLIBS=-lmsi -lole32 -lshlwapi -lshell32 -luuid
	call :msi x86 i686 x86 || goto :error
	set CGO_LDFLAGS=%CGO_LDFLAGS% -Wl,--high-entropy-va
	call :msi amd64 x86_64 x64 || goto :error
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
	set PATH=%BUILDDIR%..\.deps\%~2-w64-mingw32-native\bin;%PATH%
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
