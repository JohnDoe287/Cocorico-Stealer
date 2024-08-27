import os
import aiohttp # type: ignore
from main import error_handler

@staticmethod
async def upload_uguu(path: str) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            with open(path, 'rb') as file:
                form = aiohttp.FormData()
                form.add_field('file', file, filename=os.path.basename(path))
                async with session.post('https://uguu.se/api.php?d=upload', data=form) as response:
                    data = await response.json()
                    if "url" in data:
                        return data.get("url")
                    else:
                        return None
    except Exception as e:
        error_handler(f"uguu error - {str(e)}")
        return None