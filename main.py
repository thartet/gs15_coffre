import argparse
import re
from client import *
from server import *
import sys


def initializeParser():
    """
    Initialize the parser for the program
    returns the arguments
    """
    parser = argparse.ArgumentParser(prog="GS15 vault", description="Vault project for the GS15 course", usage="Usage ./main.py -s [-p]\n ./main.py -c [-ip] [-p]")
    parser.add_argument("-s", "--serverMode", help="Activate the server mode for the program",action="store_true", default=False)
    parser.add_argument("-c", "--clientMode", help="Activate the client mode for the program",action="store_true", default=False)
    parser.add_argument("-ip", "--ipAddress", type=str, help="Choose an IP address to transmit data", required=False, default="127.0.0.1")
    parser.add_argument("-p", "--port", type=int, help="Choose a port to transmit data", required=False, default=9999)
    args = parser.parse_args()
    return args


def errorManagement(errorCode):
    switcher = {
        0: "The program can't be in server and client mode at the same time.",
        1: "The port number is invalid.",
        2: "The IP address is invalid.",
        3: "Shutting down the program..."
    }
    print(switcher.get(errorCode))


def testArgs(args):
    """
    Test the arguments passed to the program
    args: the arguments passed to the program
    """
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


def main():
    """
    Main function of the program
    """
    args = initializeParser()
    testArgs(args)
    if args.serverMode == True:
        serverMode(args)
    elif args.clientMode == True:
        clientMode(args)
    else:
        print("No mode selected. Use --help to see usage details.")
        sys.exit(1)

if __name__ == '__main__':
    main()
