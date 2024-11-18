import argparse
import re
from client import *
from server import *

#Cette fonction permet de créer un parser pour faire des argument au programme
def initializeParser():
    parser = argparse.ArgumentParser(prog="coffre-fort GS15", description="Projet de coffre fort pour l'UE GS15", usage="Usage ./main.py -s [-p]\n ./main.py -c [-ip] [-p]")
    parser.add_argument("-s", "--serverMode", help="Passe le programme en mode Serveur",action="store_true", default=False)
    parser.add_argument("-c", "--clientMode", help="Passe le programme en mode Client",action="store_true", default=False)
    parser.add_argument("-ip", "--ipAddress", type=str, help="chosi une adresse IP pour transmettre de la donnée", required=False, default="127.0.0.1")
    parser.add_argument("-p", "--port", type=int, help="choisi un port pour transmettre la donnée", required=False, default=999)
    args = parser.parse_args()
    return args
#Cette fonction permet de tester les arguments pour vérifier s'ils sont utilisables pour le programme
def testArgs(args):
    validArgs = True
    regexIP = re.compile("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
    if args.serverMode == True and args.clientMode == True:
        print("Error: Le programme ne peut pas être à la fois client et serveur.\n")
        validArgs = False
    if args.port < 0 or args.port > 65535:
        print("Error: le numéro de port doit être un nombre entre 0 et 65535\n")
        validArgs = False
    if not bool(re.search(regexIP, args.ipAddress)):
        print("Error: invalid IP address\n")
        validArgs = False
    if validArgs == False :
        print("Shuting down program...")
        args.clientMode = False
        args.serverMode = False
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
