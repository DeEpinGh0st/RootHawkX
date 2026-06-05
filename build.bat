@echo off
setlocal

set APP_NAME=roothawkx
set OUTPUT_DIR=build
set CGO_ENABLED=0

if not exist %OUTPUT_DIR% mkdir %OUTPUT_DIR%

echo Building for Linux amd64...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -o %OUTPUT_DIR%\%APP_NAME%_linux_amd64 roothawk.go

echo Building for Linux x86 (386)...
set GOOS=linux
set GOARCH=386
go build -ldflags="-s -w" -o %OUTPUT_DIR%\%APP_NAME%_linux_386 roothawk.go

echo Building for Linux arm64...
set GOOS=linux
set GOARCH=arm64
go build -ldflags="-s -w" -o %OUTPUT_DIR%\%APP_NAME%_linux_arm64 roothawk.go

echo.
echo Build complete! Output files are in the '%OUTPUT_DIR%' directory.
endlocal
