import socket
from DiffieHelman import *
from Cobra import *
from hash import *
from Hmac import *
from rsa import *
from sha256 import *
from zpk import *

#fonction permettant de créer un compte côté client
#à faire: trouver un moyen de transmettre le mot de passe de manière non-clairs
def clientCreateAccount(clientSock):
    username = input("Entrez votre nom d'utilisateur: ")
    clientSock.send(username.encode())
    password = input("Entrez votre mot de passe: ")
    clientSock.send(password.encode())
    receivedData = clientSock.recv(8192)
    print(receivedData.decode())

#fonction permettant de se connecter à un compte côté client
#à faire: trouver un moyen de transmettre le mot de passe de manière non-clairs
def clientLogin(clientSock):
    username = input("Entrez votre nom d'utilisateur: ")
    clientSock.send(username.encode())
    password = input("Entrez votre mot de passe: ")
    clientSock.send(password.encode())
    receivedData = clientSock.recv(8192)
    print(receivedData.decode())


def fileTransfer(key, socket):
    filePath = input("Entrez le chemin absolu du fichier: ")
    f = open(filePath, "r")
    lines = f.readlines()
    cipherData = ""
    for i in range(len(lines)):
        textBlocks = textParser(lines[i])
        for j in range(len(textBlocks)):
            cipherData += encrypt(textBlocks[j], key)
    print(cipherData)
    print(len(cipherData))
    fileHmac = hmac(key, cipherData)
    print("HMAC du fichier: ", fileHmac)
    socket.send(str(len(cipherData)).encode())
    socket.send(fileHmac.encode())
    socket.send(cipherData.encode())
    newFileName = input("Sauvegarder le fichier comme: ")
    sendMessage(key, newFileName, socket)

#fonction du programme pour le faire fonctionner en mode Client
#à faire: rajouter des options
def clientMode(args):
    clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketAddr= (args.ipAddress,args.port)
    clientSock.connect(socketAddr)
    clientPuk, clientPrk = genPublicAndPrivateKey(clientSock.getsockname()[0])
    clientSock.send(str(clientPuk).encode())
    recievedData = clientSock.recv(8192)
    serverPuk = int(recievedData.decode())
    clientSk = genSecretKey(serverPuk, clientPrk)
    ans=True
    while ans:
        print("\nBonjour ô maître T ! Que souhaitez-vous faire aujourd'hui?")
        print("1. Créer votre compte")
        print("2. Vous connecter")
        print("3. Tester les fonction de chiffrements")
        print("4. Quitter")

        ans=input("Votre choix: ")
        if ans=="1":
            clientSock.send("1".encode())
            clientCreateAccount(clientSock)
        elif ans=="2":
            clientSock.send("2".encode())
            clientLogin(clientSock)
        elif ans == "3":
            print("Quel fonction tester?")
            print("1. Cobra")
            print("2. Diffie-Helman")
            print("3. sha3")
            print("4. hmac")
            print("5. RSA")
            print("6. sha-256")
            print("7. ZPK")
            ans2=input("Votre choix: ")
            if ans2 == "1":
                cobraTest(clientSk)
            elif ans2 == "2":
                testDF()
            elif ans2 == "3":
                testSha3()
            elif ans2 == "4":
                testHmac(clientSk)
            elif ans2 == "5":
                testRSA()
            elif ans2 == "6":
                testSha256()
            elif ans2 == "7":
                testZpk() 
        elif ans=="4":
            clientSock.close()
            print("\nAu revoir!")
            ans = False
        else:
            print("\nChoix invalide, veuillez réessayer.")
