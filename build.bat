@echo off
set STARTDIR=%cd%
set OLDPATH=%PATH%

if exist deps\.prepared goto :build
:installdeps
	rmdir /s /q deps 2> NUL
	mkdir deps || goto :error
	cd deps || goto :error
	echo Downloading golang
	curl -#fo go.zip https://dl.google.com/go/go1.12.windows-amd64.zip || goto :error
	echo Downloading mingw
	rem Mirror of https://musl.cc/x86_64-w64-mingw32-native.zip
	curl -#fo mingw.zip https://download.wireguard.com/windows-toolchain/distfiles/x86_64-w64-mingw32-native-20190307.zip || goto :error
	echo Downloading patch
	rem Mirror of https://sourceforge.net/projects/gnuwin32/files/patch/2.5.9-7/patch-2.5.9-7-bin.zip
	curl -#fo patch.zip https://download.wireguard.com/windows-toolchain/distfiles/patch-2.5.9-7-bin.zip || goto :error
	echo Extracting golang
	tar -xf go.zip || goto :error
	echo Extracting mingw
	tar -xf mingw.zip || goto :error
	echo Extracting patch
	tar -xf patch.zip --strip-components 1 bin || goto :error
	echo Patching golang
	.\patch.exe -f -N -r- -d go -p1 --binary < ..\golang-runtime-dll-injection.patch || goto :error
	echo Cleaning up
	del patch.exe patch.zip go.zip mingw.zip || goto :error
	copy /y NUL .prepared > NUL || goto :error
	cd .. || goto :error

:build
	set PATH=%STARTDIR%\deps\x86_64-w64-mingw32-native\bin\;%STARTDIR%\deps\go\bin\;%PATH%
	set CC=x86_64-w64-mingw32-gcc.exe
	set CFLAGS=-O3 -Wall -std=gnu11
	set GOOS=windows
	set GOARCH=amd64
	set GOPATH=%STARTDIR%\deps\gopath
	set GOROOT=%STARTDIR%\deps\go
	set CGO_ENABLED=1
	echo Assembling resources
	windres.exe -i resources.rc -o resources.syso -O coff || goto :error
	echo Building program
	go build -ldflags="-H windowsgui -s -w" -v -o wireguard.exe || goto :error
	echo Success. Launch wireguard.exe.

:out
	set PATH=%OLDPATH%
	cd %STARTDIR%
	exit /b %errorlevel%

:error
	echo Failed with error #%errorlevel%.
	goto :out
