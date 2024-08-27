import asyncio
from main import error_handler
from computer import get_commands


async def get_command_output(command: str) -> str:
    process = await asyncio.create_subprocess_shell(command,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
    stdout, stderr = await process.communicate()
    if stderr:
        error_handler(f"get command error")
    return stdout.decode(errors="ignore")