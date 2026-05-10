@echo off
echo Building RecoverSoft Windows installer...

:: Install PyInstaller if needed
pip install pyinstaller requests psutil wmi --quiet

:: Build hidden .exe (no console window)
pyinstaller ^
    --onefile ^
    --noconsole ^
    --name "RecoverSoft" ^
    --icon "icon.ico" ^
    --add-data "tracker_windows.py;." ^
    launcher.pyw

echo.
echo Build complete!
echo Installer: dist/RecoverSoft.exe
pause
