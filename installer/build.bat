@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019 WireGuard LLC. All Rights Reserved.

for /f "tokens=3" %%a in ('findstr /r "[0-9.]*" ..\version.h') do set WIREGUARD_VERSION=%%a
set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%

set STARTDIR=%cd%
set OLDWIX=%WIX%
set WIX_CANDLE_FLAGS=-nologo -dWIREGUARD_VERSION="%WIREGUARD_VERSION%"
set WIX_LIGHT_FLAGS=-nologo -spdb

if exist .deps\prepared goto :build
:installdeps
	rmdir /s /q .deps 2> NUL
	mkdir .deps || goto :error
	cd .deps || goto :error
	echo [+] Downloading wix-binaries
	curl -#fLo wix-binaries.zip http://wixtoolset.org/downloads/v3.14.0.2812/wix314-binaries.zip || goto :error
	echo [+] Verifying wix-binaries
	for /f %%a in ('CertUtil -hashfile wix-binaries.zip SHA256 ^| findstr /r "^[0-9a-f]*$"') do if not "%%a"=="923892298f37514622c58cbbd9c2cadf2822d9bb53df8ee83aaeb05280777611" goto :error
	rem echo [+] Downloading wintun-x86
	rem curl -#fo wintun-x86.msm https://www.wintun.net/builds/wintun-x86-0.1.msm || goto :error
	rem echo [+] Verifying wintun-x86
	rem for /f %%a in ('CertUtil -hashfile wintun-x86.msm SHA256 ^| findstr /r "^[0-9a-f]*$"') do if not "%%a"=="5390762183e181804b28eb13815b6210f85a1280057b815f749b06768215f817" goto :error
	echo [+] Downloading wintun-amd64
	curl -#fo wintun-amd64.msm https://www.wintun.net/builds/wintun-amd64-0.1.msm || goto :error
	echo [+] Verifying wintun-amd64
	for /f %%a in ('CertUtil -hashfile wintun-amd64.msm SHA256 ^| findstr /r "^[0-9a-f]*$"') do if not "%%a"=="850b8e76ced2b1bbbfd601b04726b6e491d14b583694d139855c1d337ee48590" goto :error
	echo [+] Extracting wix-binaries
	mkdir wix\bin || goto :error
	tar -xf wix-binaries.zip -C wix\bin || goto :error
	echo [+] Cleaning up
	del wix-binaries.zip || goto :error
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error

:build
	set WIX=%STARTDIR%\.deps\wix\
	call :msi x86   x86 || goto :error
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

:msi
	echo [+] Compiling %1
	"%WIX%bin\candle.exe" %WIX_CANDLE_FLAGS% -dPlatform="%1" -out "%1\wireguard.wixobj" -arch %2 wireguard.wxs || exit /b %errorlevel%
	echo [+] Linking %1
	"%WIX%bin\light.exe" %WIX_LIGHT_FLAGS% -out "dist\wireguard-%1-%WIREGUARD_VERSION%.msi" "%1\wireguard.wixobj" || exit /b %errorlevel%
	goto :eof
