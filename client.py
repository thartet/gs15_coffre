import socket
from DiffieHelman import *
from Cobra import *
from hash import *
from Hmac import *
from rsa import *
from sha256 import *
from zpk import *
from maths import *
import json

#fonction permettant de créer un compte côté client
#à faire: trouver un moyen de transmettre le mot de passe de manière non-clairs
def clientCreateAccount(key, clientSock):
    username = input("Entrez votre nom d'utilisateur: ")
    sendMessage(key, username, clientSock)
    password = input("Entrez votre mot de passe: ")
    prkZpk = SHA3_256(password.encode()).hexdigest()
    sendMessage(key, prkZpk, clientSock)
    p = random_prime(256)
    pukZpk, alpha = generate_keys(p, int(prkZpk, 16))
    sendMessage(key, str(pukZpk), clientSock)
    sendMessage(key, str(alpha), clientSock)
    pukRsa, prkRsa = RSA()
    sendMessage(key, str(pukRsa), clientSock)
    userData= {}
    userData['username'] = username
    userData['password'] = password
    userData['prkZpk'] = int(prkZpk, 16)
    userData['pukZpk'] = pukZpk
    userData['alpha'] = alpha
    userData['prkRsa'] = prkRsa
    userData['pukRsa'] = pukRsa
    userData['alpha'] = alpha
    userData = json.dumps(userData, indent=4)
    f = open("userData.json", "w")
    f.write(userData)



#fonction permettant de se connecter à un compte côté client
#à faire: trouver un moyen de transmettre le mot de passe de manière non-clairs
def clientLogin(key, clientSock):
    isConnected = False
    certificateToVerify = reciveMessage(key, clientSock)
    sendMessage(key, certificateToVerify, clientSock)
    isLegit = reciveMessage(key, clientSock)
    if isLegit == "True":
        username = input("Rentrez votre identifiant: ")
        sendMessage(key, username, clientSock)
        motDePasse = input("Rentrez votre mot de passe: ")
        motDePasse = SHA3_256(motDePasse.encode()).hexdigest()
        sendMessage(key, motDePasse, clientSock)
        loginMessage = reciveMessage(key, clientSock)
        print(loginMessage)
        if loginMessage == "Connection accepte":
            isConnected = True
            return isConnected  


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
        print("4. Générer une paire de clés RSA")
        print("5. Quitter")

        choice=input("Votre choix: ")
        if choice=="1":
            sendMessage(clientSk, "1", clientSock)
            clientCreateAccount(clientSk, clientSock)
        elif choice=="2":
            sendMessage(clientSk, "2", clientSock)
            isConnected = clientLogin(clientSk, clientSock)
            if isConnected:
                print("Que voulez-vous faire?")
                print("1. Déposer un fichier")
                print("2. Consulter un fihier")
                ans2=input("Votre choix: ")
                if ans2 == "1":
                    sendMessage(clientSk, "1", clientSock)
                    fileTransfer(clientSk, clientSock)
        elif choice == "3":
            print("Quel fonction tester?")
            print("1. Cobra")
            print("2. Diffie-Helman")
            print("3. SHA3-256")
            print("4. HMAC SHA-256")
            print("5. RSA")
            print("6. SHA-256")
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
        elif choice=="4":
            generate_keyfiles()
        elif choice=="5":
            clientSock.close()
            print("\nAu revoir!")
            ans = False
        else:
            print("\nChoix invalide, veuillez réessayer.")
