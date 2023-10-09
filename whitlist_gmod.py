import time
from rcon.source import Client
import random
import re
import subprocess
import socket
import a2s

def playercount():
    address = ("172.18.0.2", 27015)
    server_info = a2s.info(address)
    player_count = server_info.player_count
    return player_count

def sendcommand(command):
    #Change this to what you put in your startup options
    port = 27015
    password = ""
    with Client("172.18.0.2", port, passwd=password) as client:
        response = client.run(command)

        lines = response.split('\n')
        # Récupération des informations du serveur
        server_info = {}
        for line in lines:
            if line.startswith("hostname"):
                server_info["hostname"] = line.split(":")[1].strip()
            elif line.startswith("version"):
                server_info["version"] = line.split(":")[1].strip()
            elif line.startswith("udp/ip"):
                server_info["udp/ip"] = line.split(":")[1].strip()
            elif line.startswith("map"):
                server_info["map"] = line.split(":")[1].strip()
            elif line.startswith("players"):
                server_info["players"] = line.split(":")[1].strip().split()[0]
        if server_info["players"] == 0:
            sys.exit(0)
        # Définition du pattern regex pour les adresses IP
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        # Recherche des adresses IP dans les données
        ip_addresses = re.findall(ip_pattern, response)

        # Affichage des adresses IP trouvées
        for ip in ip_addresses:
            if ip != "0.0.0.0":
                subprocess.run(["ipset", "add", "ByPass", str(ip)])

def sendcommandlua(command):
    #Change this to what you put in your startup options
    port = 27015
    password = ""
    with Client("172.18.0.2", port, passwd=password) as client:
        response = client.run(command)
        print(response)

if playercount() != 0:
    #if sendcommandlua("lua_run print(#player.GetAll())") != 0:
    sendcommand("status")

