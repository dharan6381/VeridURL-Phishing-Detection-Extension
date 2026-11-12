@echo off
echo =======================================================================
echo               VeridURL Local API Engine Installer & Runner            
echo =======================================================================
echo.

:: Check for Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not added to your system PATH.
    echo Please install Python 3.9+ and try again.
    pause
    exit /b 1
)

:: Navigate to backend folder
cd veridurl_backend

:: Setup virtual environment
if not exist "venv" (
    echo [INFO] Creating Python virtual environment (venv)...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

:: Activate and install requirements
echo [INFO] Activating virtual environment and installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Dependency installation failed.
    pause
    exit /b 1
)

echo.
echo =======================================================================
echo [SUCCESS] Setup complete. Starting VeridURL API Local Server...
echo Address: http://127.0.0.1:8000
echo =======================================================================
echo.

uvicorn api_server:app --reload --host 127.0.0.1 --port 8000
pause
