@echo off
echo FastPass Project Status Checker
echo ==================================================

cd /d "C:\Dev\fast_pass"

echo Generating fresh repomix analysis...
repomix --output temp_status_check.xml .

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to generate repomix analysis
    exit /b 1
)

echo [SUCCESS] Repomix analysis generated

echo.
echo Sending to Gemini for analysis...
echo.

type temp_status_check.xml | gemini -p "Claude here. Act as a critical technical reviewer. I have a FastPass project (universal file encryption/decryption tool). Compare the codebase against the specification in dev/fast_pass_specification.md and provide: 1) COMPLETION STATUS - is everything implemented? 2) CORRECTNESS ANALYSIS 3) MISSING FEATURES 4) CRITICAL ISSUES 5) RECOMMENDATIONS. Be thorough and critical - focus on compliance with specification."

echo.
echo [SUCCESS] Status check completed!

echo.
echo Cleaning up...
del temp_status_check.xml