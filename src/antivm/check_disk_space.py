import ctypes
import sys
import win32api # type: ignore
import psutil # type: ignore

from main import error_handler # type: ignore

async def check_disk_space(self) -> bool:
    try:
        total_disk_space_gb = sum(psutil.disk_usage(drive.mountpoint).total for drive in psutil.disk_partitions()) / (1024 ** 3)
        if total_disk_space_gb < 50:
            ctypes.windll.kernel32.ExitProcess(0)
        min_disk_space_gb = 50
        if len(sys.argv) > 1:
            min_disk_space_gb = float(sys.argv[1])
        free_space_gb = win32api.GetDiskFreeSpaceEx()[1] / 1073741824
        if free_space_gb < min_disk_space_gb:
            ctypes.windll.kernel32.ExitProcess(0)
    except Exception as e:
        error_handler(f"anti vm disk space error - {str(e)}")
