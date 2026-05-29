@echo off
chcp 65001 >nul
echo ===================================
echo   NetScan Pro Build Script
echo ===================================

set GOROOT=C:\Go64\go
set GOPATH=%USERPROFILE%\go64
set PATH=C:\Go64\go\bin;%USERPROFILE%\go64\bin;%PATH%
set GOPROXY=https://goproxy.cn,direct

echo.
echo [1/3] Installing Go dependencies...
cd /d "%~dp0"
go mod tidy
if %errorlevel% neq 0 (
    echo Failed to install Go dependencies
    exit /b 1
)

echo.
echo [2/3] Building frontend...
cd frontend
call npm install
call npm run build
cd ..
if %errorlevel% neq 0 (
    echo Failed to build frontend
    exit /b 1
)

echo.
echo [3/3] Building Wails application...
wails build -platform windows/amd64 -nsis
if %errorlevel% neq 0 (
    wails build -platform windows/amd64
    if %errorlevel% neq 0 (
        echo Failed to build Wails application
        exit /b 1
    )
)

echo.
echo ===================================
echo   Build completed!
echo   Output: build\bin\netscan.exe
echo   Installer: build\bin\netscan-amd64-installer.exe
echo ===================================
pause
