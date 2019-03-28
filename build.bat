@echo off
set STARTDIR=%cd%
set OLDPATH=%PATH%
set CURL_VER=7.64.1

if exist .deps\prepared goto :build
:installdeps
	rmdir /s /q .deps 2> NUL
	mkdir .deps || goto :error
	cd .deps || goto :error
	where /q $path:tar.exe || goto :unzip
	tar --help | find "bsdtar"	>NUL && goto :curl
:unzip
	where /q $path:unzip.exe && goto :tar
	echo [+] Downloading unzip
	CertUtil -urlcache -split -f http://stahlworks.com/dev/unzip.exe unzip.exe
	if not exist unzip.exe goto :error
	echo [+] Verifying unzip
	for /f "tokens=1-20" %%a in ('CertUtil -hashfile unzip.exe SHA1 ^| findstr /r /c:"^[0-9a-f ]*$"') do set HASH=%%a%%b%%c%%d%%e%%f%%g%%h%%i%%j%%k%%l%%m%%n%%o%%p%%q%%r%%s%%t
	if /i not "%HASH%"=="e1652b058195db3f5f754b7ab430652ae04a50b8" goto :error
:tar
	echo [+] Downloading libarchive
	CertUtil -urlcache -split -f http://downloads.sourceforge.net/ezwinports/libarchive-3.3.1-w32-bin.zip libarchive.zip
	if not exist libarchive.zip goto :error
	echo [+] Verifying libarchive
	for /f "tokens=1-20" %%a in ('CertUtil -hashfile libarchive.zip SHA1 ^| findstr /r /c:"^[0-9a-f ]*$"') do set HASH=%%a%%b%%c%%d%%e%%f%%g%%h%%i%%j%%k%%l%%m%%n%%o%%p%%q%%r%%s%%t
	if /i not "%HASH%"=="9c5ca423b777d80b0ed2d7edf0c9a904a8a00db3" goto :error
	echo [+] Extracting tar
	unzip -ojq libarchive.zip bin/* || goto :error
	copy /y bsdtar.exe tar.exe || goto :error
:curl
	where.exe /q $path:curl.exe && goto :golang
	echo [+] Downloading curl
	CertUtil -urlcache -split -f https://curl.haxx.se/windows/dl-%CURL_VER%/curl-%CURL_VER%-win64-mingw.zip curl.zip
	if not exist curl.zip goto :error
	echo [+] Verifying curl
	for /f "tokens=1-20" %%a in ('CertUtil -hashfile curl.zip SHA1 ^| findstr /r /c:"^[0-9a-f ]*$"') do set HASH=%%a%%b%%c%%d%%e%%f%%g%%h%%i%%j%%k%%l%%m%%n%%o%%p%%q%%r%%s%%t
	if /i not "%HASH%"=="c83c099083c35ebf7e9a654db3efc1b886895f6b" goto :error
	echo [+] Extracting curl.exe
	unzip -ojq curl.zip curl-%CURL_VER%-win64-mingw/bin/* || goto :error
:golang
	echo [+] Downloading golang
	curl -#fo go.zip https://dl.google.com/go/go1.12.windows-amd64.zip || goto :error
	echo [+] Verifying golang
	for /f "tokens=1-20" %%a in ('CertUtil -hashfile go.zip SHA1 ^| findstr /r /c:"^[0-9a-f ]*$"') do set HASH=%%a%%b%%c%%d%%e%%f%%g%%h%%i%%j%%k%%l%%m%%n%%o%%p%%q%%r%%s%%t
	if /i not "%HASH%"=="13e3caaeab014658489de7db1ad98d2e34369b32" goto :error
	echo [+] Downloading mingw
	rem Mirror of https://musl.cc/x86_64-w64-mingw32-native.zip
	curl -#fo mingw.zip https://download.wireguard.com/windows-toolchain/distfiles/x86_64-w64-mingw32-native-20190307.zip || goto :error
	echo [+] Verifying mingw
	for /f "tokens=1-20" %%a in ('CertUtil -hashfile mingw.zip SHA1 ^| findstr /r /c:"^[0-9a-f ]*$"') do set HASH=%%a%%b%%c%%d%%e%%f%%g%%h%%i%%j%%k%%l%%m%%n%%o%%p%%q%%r%%s%%t
	if /i not "%HASH%"=="0326ee409c07b12265bc5f15a5514eee14569690" goto :error
	echo [+] Downloading patch
	rem Mirror of https://sourceforge.net/projects/gnuwin32/files/patch/2.5.9-7/patch-2.5.9-7-bin.zip with fixed manifest
	curl -#fo patch.zip https://download.wireguard.com/windows-toolchain/distfiles/patch-2.5.9-7-bin-fixed-manifest.zip || goto :error
	echo [+] Verifying patch
	for /f "tokens=1-20" %%a in ('CertUtil -hashfile patch.zip SHA1 ^| findstr /r /c:"^[0-9a-f ]*$"') do set HASH=%%a%%b%%c%%d%%e%%f%%g%%h%%i%%j%%k%%l%%m%%n%%o%%p%%q%%r%%s%%t
	if /i not "%HASH%"=="95a3997ca06c9cd2f28171de16698d24ac8cfd00" goto :error
	echo [+] Extracting golang
	tar -xf go.zip || goto :error
	echo [+] Extracting mingw
	tar -xf mingw.zip || goto :error
	echo [+] Extracting patch
	tar -xf patch.zip --strip-components 1 bin || goto :error
	echo [+] Patching golang
	.\patch.exe -f -N -r- -d go -p1 --binary < ..\golang-runtime-dll-injection.patch || goto :error
	echo [+] Cleaning up
	del patch.exe patch.zip go.zip mingw.zip || goto :error
	del unzip.exe libarchive.zip curl.zip 2>NUL
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error

:build
	set PATH=%STARTDIR%\.deps\x86_64-w64-mingw32-native\bin\;%STARTDIR%\.deps\go\bin\;%PATH%
	set CC=x86_64-w64-mingw32-gcc.exe
	set CFLAGS=-O3 -Wall -std=gnu11
	set GOOS=windows
	set GOARCH=amd64
	set GOPATH=%STARTDIR%\.deps\gopath
	set GOROOT=%STARTDIR%\.deps\go
	set CGO_ENABLED=1
	echo [+] Assembling resources
	windres.exe -i resources.rc -o resources.syso -O coff || goto :error
	echo [+] Building program
	go build -ldflags="-H windowsgui -s -w" -v -o wireguard.exe || goto :error
	echo [+] Success. Launch wireguard.exe.

:out
	set PATH=%OLDPATH%
	cd %STARTDIR%
	exit /b %errorlevel%

:error
	echo [-] Failed with error #%errorlevel%.
	goto :out
