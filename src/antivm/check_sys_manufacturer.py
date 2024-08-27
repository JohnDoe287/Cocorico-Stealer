import asyncio
import ctypes

from main import error_handler


async def check_system_manufacturer(self) -> None:
    try:
        process1 = await asyncio.create_subprocess_shell('wmic computersystem get Manufacturer',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
        stdout1, stderr1 = await process1.communicate()

        process2 = await asyncio.create_subprocess_shell('wmic path Win32_ComputerSystem get Manufacturer',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
        stdout2, stderr2 = await process2.communicate()

        if b'VMware' in stdout1 or b"vmware" in stdout2.lower():
            ctypes.windll.kernel32.ExitProcess(0)
    except Exception as e:
        error_handler(f"manufacturer error - {str(e)}")
