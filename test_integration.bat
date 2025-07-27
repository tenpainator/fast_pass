@echo off
echo FastPass Integration Test
echo ========================

if "%1"=="" (
    echo Usage: test_integration.bat "path\to\file.pdf"
    exit /b 1
)

set "FILEPATH=%~1"
set "FASTPASS_DIR=%~dp0"

echo Testing file: %FILEPATH%
echo FastPass directory: %FASTPASS_DIR%

echo.
echo Checking encryption status...
cd "%FASTPASS_DIR%"
python -m src check-password -i "%FILEPATH%"

echo.
echo Test completed.
pause