@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3.12) else (set PY=python)

if not exist .venv (
    %PY% -m venv .venv || goto :fail
)
call .venv\Scripts\activate.bat || goto :fail

python -m pip install --upgrade pip || goto :fail
python -m pip install pyinstaller==6.15.0 cryptography==45.0.0 || goto :fail

pyinstaller vivo-decryptor.spec --noconfirm --clean || goto :fail

echo.
echo Output: %CD%\dist\VivoDecryptor.exe
certutil -hashfile dist\VivoDecryptor.exe SHA256
echo.
echo Build finished.
pause
exit /b 0

:fail
echo.
echo Build FAILED.
pause
exit /b 1
