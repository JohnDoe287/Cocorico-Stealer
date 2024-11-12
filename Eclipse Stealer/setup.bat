@echo off
setlocal

set "URL_PYTHON_310=https://www.python.org/ftp/python/3.10.9/python-3.10.9-amd64.exe"
set "URL_PYTHON_311=https://www.python.org/ftp/python/3.11.7/python-3.11.7-amd64.exe"

where python3.10 >nul 2>nul
if %errorlevel% neq 0 (
    echo Python 3.10 is not installed. Downloading and installing...
    powershell -Command "Invoke-WebRequest -Uri %URL_PYTHON_310% -OutFile python-3.10.9-amd64.exe"
    start /wait python-3.10.9-amd64.exe /quiet InstallAllUsers=1 PrependPath=1
    echo Python 3.10 installed successfully.
) else (
    echo Python 3.10 is already installed.
)

where python3.11 >nul 2>nul
if %errorlevel% neq 0 (
    echo Python 3.11 is not installed. Downloading and installing...
    powershell -Command "Invoke-WebRequest -Uri %URL_PYTHON_311% -OutFile python-3.11.7-amd64.exe"
    start /wait python-3.11.7-amd64.exe /quiet InstallAllUsers=1 PrependPath=1
    echo Python 3.11 installed successfully.
) else (
    echo Python 3.11 is already installed.
)

where python3.10 >nul 2>nul
if %errorlevel% eq 0 (
    echo Upgrading pip for Python 3.10...
    python3.10 -m pip install --upgrade pip
) else (
    echo Python 3.10 is not available, skipping pip upgrade for Python 3.10.
)

where python3.11 >nul 2>nul
if %errorlevel% eq 0 (
    echo Upgrading pip for Python 3.11...
    python3.11 -m pip install --upgrade pip
) else (
    echo Python 3.11 is not available, skipping pip upgrade for Python 3.11.
)

where python3.10 >nul 2>nul
if %errorlevel% eq 0 (
    echo Installing dependencies with pip for Python 3.10...
    python3.10 -m pip install -r requirements.txt
) else (
    echo Python 3.10 is not available, skipping dependency installation for Python 3.10.
)

where python3.11 >nul 2>nul
if %errorlevel% eq 0 (
    echo Installing dependencies with pip for Python 3.11...
    python3.11 -m pip install -r requirements.txt
) else (
    echo Python 3.11 is not available, skipping dependency installation for Python 3.11.
)

echo Cleaning up installation files...
del python-3.10.9-amd64.exe
del python-3.11.7-amd64.exe

echo Installation completed!
endlocal
pause

