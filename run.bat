@echo off
color 0a
echo =========================================
echo       INITIATING PRIVACY_OS
echo =========================================
echo.

REM 1. Start the FastAPI backend in a separate terminal window
echo Starting backend server...
start "PrivacyOS Backend" cmd /k "cd backend && uvicorn main:app --reload"

REM 2. Wait 3 seconds to give the server time to boot up
timeout /t 3 /nobreak > NUL

REM 3. Open the main index screen in your default web browser
echo Opening frontend...
start frontend\index.html

echo.
echo System is live! You can close this window.