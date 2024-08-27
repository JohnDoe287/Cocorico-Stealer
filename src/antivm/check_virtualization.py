import asyncio
import ctypes

from main import error_handler


async def check_for_virtualization(self) -> None:
    try:
        process = await asyncio.create_subprocess_shell('wmic path win32_VideoController get name',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
        stdout, stderr = await process.communicate()
        video_controller_info = stdout.decode(errors='ignore').splitlines()
        if any(x.lower() in video_controller_info[2].strip().lower() for x in ("virtualbox", "vmware")):
            ctypes.windll.kernel32.ExitProcess(0)
    except Exception as e:
        error_handler(f"virtualization error - {str(e)}")
