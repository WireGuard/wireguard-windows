@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019 WireGuard LLC. All Rights Reserved.

for /f "tokens=3" %%a in ('findstr /r "WIREGUARD_WINDOWS_VERSION_STRING.*[0-9.]*" ..\version.h') do set WIREGUARD_VERSION=%%a
set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%

set STARTDIR=%cd%
set OLDWIX=%WIX%
set WIX_CANDLE_FLAGS=-nologo -dWIREGUARD_VERSION="%WIREGUARD_VERSION%"
set WIX_LIGHT_FLAGS=-nologo -spdb -sice:ICE30

if exist .deps\prepared goto :build
:installdeps
	rmdir /s /q .deps 2> NUL
	mkdir .deps || goto :error
	cd .deps || goto :error
	call :download wintun-x86.msm https://www.wintun.net/builds/wintun-x86-0.1.msm 49b4f142c699d9d04c7506b85dc2ab614c4761643fbb44a68c81de2f6b6ceeb9 || goto :error
	call :download wintun-amd64.msm https://www.wintun.net/builds/wintun-amd64-0.1.msm d8f2d162f2da067b2266a367e9bb0a5190e437ed596b69bfef92bf41d45cf305 || goto :error
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
	if "%SigningCertificate%"=="" goto :build_sfx
	if "%TimestampServer%"=="" goto :build_sfx
	echo [+] Signing
	signtool.exe sign /sha1 "%SigningCertificate%" /fd sha256 /tr "%TimestampServer%" /td sha256 /d "WireGuard Setup" "dist\wireguard-*-%WIREGUARD_VERSION%.msi" || goto :error

:build_sfx
	rem TODO: Build SFX bundle with all MSIs.

:out
	set WIX=%OLDWIX%
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
	"%WIX%bin\candle.exe" %WIX_CANDLE_FLAGS% -dPlatform="%~1" -out "%~1\wireguard.wixobj" -arch %2 wireguard.wxs || exit /b %errorlevel%
	echo [+] Linking %1
	"%WIX%bin\light.exe" %WIX_LIGHT_FLAGS% -out "dist\wireguard-%~1-%WIREGUARD_VERSION%.msi" "%~1\wireguard.wixobj" || exit /b %errorlevel%
	goto :eof
