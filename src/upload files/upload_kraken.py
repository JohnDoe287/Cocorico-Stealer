import os
import aiohttp # type: ignore

from main import error_handler


@staticmethod
async def upload_krakenfiles(path: str) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            with open(path, 'rb') as file:
                form = aiohttp.FormData()
                form.add_field('file', file, filename=os.path.basename(path))
                async with session.post('https://krakenfiles.com/api/v1/file/upload', data=form) as response:
                    data = await response.json()
                    if "data" in data and "file" in data["data"]:
                        return data["data"]["file"]["url"]
                    else:
                        return None
    except Exception as e:
        error_handler(f"krakenfiles error - {str(e)}")
        return None