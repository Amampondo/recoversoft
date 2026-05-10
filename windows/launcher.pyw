"""
RecoverSoft Silent Launcher
Runs tracker_windows.py with zero visible window.
This is what gets compiled to .exe
"""
import subprocess
import sys
import os
from pathlib import Path

def run_hidden():
    """Launch tracker as hidden subprocess."""
    tracker = Path(__file__).parent / 'tracker_windows.py'
    
    # Windows STARTUPINFO to hide window completely
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    subprocess.Popen(
        [sys.executable, str(tracker)],
        startupinfo=si,
        creationflags=subprocess.CREATE_NO_WINDOW,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

if __name__ == "__main__":
    run_hidden()
