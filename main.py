import argparse
import re
from client import *
from server import *
import random

#Cette fonction permet de créer un parser pour faire des argument au programme
def initializeParser():
    parser = argparse.ArgumentParser(prog="coffre-fort GS15", description="Projet de coffre fort pour l'UE GS15", usage="Usage ./main.py -s [-p]\n ./main.py -c [-ip] [-p]")
    parser.add_argument("-s", "--serverMode", help="Passe le programme en mode Serveur",action="store_true", default=False)
    parser.add_argument("-c", "--clientMode", help="Passe le programme en mode Client",action="store_true", default=False)
    parser.add_argument("-ip", "--ipAddress", type=str, help="Choisis une adresse IP pour transmettre de la donnée", required=False, default="127.0.0.1")
    parser.add_argument("-p", "--port", type=int, help="Choisis un port pour transmettre la donnée", required=False, default=9999)
    args = parser.parse_args()
    return args


def errorManagement(errorCode):
    switcher = {
        0: "Le programme ne peut pas être à la fois client et serveur.",
        1: "Le numéro de port doit être un nombre entre 0 et 65535.",
        2: "L'adresse IP est invalide.",
        3: "Extinction du programme en cours..."
    }
    print(switcher.get(errorCode))

#Cette fonction permet de tester les arguments pour vérifier s'ils sont utilisables pour le programme
def testArgs(args):
    validArgs = True
    regexIP = re.compile("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
    if args.serverMode == True and args.clientMode == True:
        errorManagement(0)
        validArgs = False
    if args.port < 0 or args.port > 65535:
        errorManagement(1)
        validArgs = False
    if not bool(re.search(regexIP, args.ipAddress)):
        errorManagement(2)
        validArgs = False
    if validArgs == False :
        errorManagement(3)
        args.clientMode = False
        args.serverMode = False

#Cette fonction permet de générer une clé de session aléatoire dans un bitarray
def genSessionKey():
    sessionKey=''
    while True:
        keySize=int(input("Quelle taille de clé voulez-vous générer? (128, 192 ou 256): "))
        if keySize == 128:
            sessionKey=format(random.getrandbits(128), '0128b')
            break
        elif keySize == 192:
            sessionKey=format(random.getrandbits(192), '0192b')
            break
        elif keySize == 256:
            sessionKey=format(random.getrandbits(256), '0256b')
            break
        else:
            print("Wrong key size")
    return sessionKey

def main():
    ans=True
    while ans:
        print("Bonjour ô maître T ! Que souhaitez-vous faire aujourd'hui?")
        print("1. Créer votre compte")
        print("2. Vous connecter")
        print("3. Quitter")
#fonction principale du programme
def main():
    args = initializeParser()
    testArgs(args)
    if args.serverMode == True:
        serverMode(args)
    elif args.clientMode == True:
        clientMode(args)

if __name__ == '__main__':
    main()
