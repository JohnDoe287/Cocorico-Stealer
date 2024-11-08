@echo off
setlocal

set "URL_PYTHON_310=https://www.python.org/ftp/python/3.10.9/python-3.10.9-amd64.exe"
set "URL_PYTHON_311=https://www.python.org/ftp/python/3.11.7/python-3.11.7-amd64.exe"

echo Downloading Python 3.10.9...
powershell -Command "Invoke-WebRequest -Uri %URL_PYTHON_310% -OutFile python-3.10.9-amd64.exe"

echo Downloading Python 3.11.7...
powershell -Command "Invoke-WebRequest -Uri %URL_PYTHON_311% -OutFile python-3.11.7-amd64.exe"

echo Installing Python 3.10.9...
start /wait python-3.10.9-amd64.exe /quiet InstallAllUsers=1 PrependPath=1

echo Installing Python 3.11.7...
start /wait python-3.11.7-amd64.exe /quiet InstallAllUsers=1 PrependPath=1

echo Upgrading pip for Python 3.10.9...
python3.10 -m pip install --upgrade pip

echo Upgrading pip for Python 3.11.7...
python3.11 -m pip install --upgrade pip

echo Installing dependencies with pip for Python 3.10.9...
python3.10 -m pip install -r requirements.txt

echo Installing dependencies with pip for Python 3.11.7...
python3.11 -m pip install -r requirements.txt

echo Cleaning up installation files...
del python-3.10.9-amd64.exe
del python-3.11.7-amd64.exe

echo Installation completed!
endlocal
pause
