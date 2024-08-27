import aiohttp # type: ignore
import os

from main import error_handler


@staticmethod
async def upload_catbox(path: str) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            with open(path, 'rb') as file:
                form = aiohttp.FormData()
                form.add_field('fileToUpload', file, filename=os.path.basename(path))
                form.add_field('reqtype', 'fileupload')
                form.add_field('userhash', '')
                async with session.post('https://catbox.moe/user/api.php', data=form) as response:
                    result = await response.text()
                    if "catbox.moe" in result:
                        return result
                    else:
                        return None
    except Exception as e:
        error_handler(f"catbox error - {str(e)}")
        return None