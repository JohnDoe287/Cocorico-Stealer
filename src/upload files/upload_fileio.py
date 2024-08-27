import os
import aiohttp # type: ignore
from main import error_handler

@staticmethod
async def upload_fileio(path: str) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            with open(path, 'rb') as file:
                form = aiohttp.FormData()
                form.add_field('file', file, filename=os.path.basename(path))
                async with session.post('https://file.io/', data=form) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("link")
                    else:
                        return None
    except Exception as e:
        error_handler(f"fileio error - {str(e)}")
        return None