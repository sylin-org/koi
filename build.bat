@echo off
setlocal

echo.
echo  Building Koi...
echo.

:: Build release binary
cargo build --release
if %errorlevel% neq 0 (
    echo.
    echo  BUILD FAILED
    exit /b %errorlevel%
)

:: Run tests
echo.
echo  Running tests...
echo.
cargo test --release
if %errorlevel% neq 0 (
    echo.
    echo  TESTS FAILED
    exit /b %errorlevel%
)

:: Prepare dist folder
if not exist dist mkdir dist

:: Copy binary
copy /Y target\release\koi.exe dist\koi.exe >nul
if %errorlevel% neq 0 (
    echo.
    echo  Failed to copy binary to dist\
    exit /b %errorlevel%
)

:: Get version from Cargo.toml
for /f "tokens=3 delims= " %%v in ('findstr /r "^version" Cargo.toml') do (
    set VERSION=%%~v
)

echo.
echo  Build complete.
echo  Binary:  dist\koi.exe
echo  Version: %VERSION%
echo.

endlocal
