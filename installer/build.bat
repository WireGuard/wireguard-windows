@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019 WireGuard LLC. All Rights Reserved.

set OLDPATHEXT=%PATHEXT%
set PATHEXT=.exe

for /f "tokens=3" %%a in ('findstr /r "WIREGUARD_WINDOWS_VERSION_STRING.*[0-9.]*" ..\version.h') do set WIREGUARD_VERSION=%%a
set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%

set STARTDIR=%cd%
set OLDWIX=%WIX%
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
	call :download wintun-x86.msm https://www.wintun.net/builds/wintun-x86-0.2.msm d245f20132e46c851a708829ea88979727a8d8ad7d9f9015408d8b1a35295470 || goto :error
	call :download wintun-amd64.msm https://www.wintun.net/builds/wintun-amd64-0.2.msm 25a4d4086037f3e99a8d42ccb3450dcbf233e23b28d6e57708141974d8c63e0e || goto :error
	call :download wix-binaries.zip http://wixtoolset.org/downloads/v3.14.0.2812/wix314-binaries.zip 923892298f37514622c58cbbd9c2cadf2822d9bb53df8ee83aaeb05280777611 || goto :error
	echo [+] Extracting wix-binaries.zip
	mkdir wix\bin || goto :error
	tar -xf wix-binaries.zip -C wix\bin || goto :error
	echo [+] Cleaning up wix-binaries.zip
	del wix-binaries.zip || goto :error
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error

:build
	set WIX=%STARTDIR%\.deps\wix\
	call :msi x86 x86 || goto :error
	call :msi amd64 x64 || goto :error
	if exist ..\sign.bat call ..\sign.bat
	if "%SigningCertificate%"=="" goto :out
	if "%TimestampServer%"=="" goto :out
	echo [+] Signing
	signtool sign /sha1 "%SigningCertificate%" /fd sha256 /tr "%TimestampServer%" /td sha256 /d "WireGuard Setup" "dist\wireguard-*-%WIREGUARD_VERSION%.msi" || goto :error

:out
	set WIX=%OLDWIX%
	set PATHEXT=%OLDPATHEXT%
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
	goto :eof

:msi
	echo [+] Compiling %1
	"%WIX%bin\candle" %WIX_CANDLE_FLAGS% -dPlatform="%~1" -out "%~1\wireguard.wixobj" -arch %2 wireguard.wxs || exit /b %errorlevel%
	echo [+] Linking %1
	"%WIX%bin\light" %WIX_LIGHT_FLAGS% -out "dist\wireguard-%~1-%WIREGUARD_VERSION%.msi" "%~1\wireguard.wixobj" || exit /b %errorlevel%
	goto :eof
