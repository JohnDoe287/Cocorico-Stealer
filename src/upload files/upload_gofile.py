import os
import aiohttp # type: ignore
from main import error_handler


@staticmethod
async def getserver() -> str:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://api.gofile.io/getServer") as request:
                data = await request.json()
                return data["data"]["server"]
    except Exception as e:
        error_handler(f"gofile server error - {str(e)}")
        return "store1"

@staticmethod
async def upload_gofile(path: str) -> str:
    try:
        server = await getserver()
        async with aiohttp.ClientSession() as session:
            with open(path, 'rb') as file:
                form = aiohttp.FormData()
                form.add_field('file', file, filename=os.path.basename(path))
                async with session.post(f'https://{server}.gofile.io/uploadFile', data=form) as response:
                    data = await response.json()
                    if response.status == 200 and "data" in data:
                        return data["data"]["downloadPage"]
                    else:
                        return None
    except Exception as e:
        error_handler(f"gofile error - {str(e)}")
        return None