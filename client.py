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

def clientCreateAccount(key, clientSock):
    """
    Function to create an account on the client side
    key: the secret key used for encryption
    clientSock: the client socket
    """
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

    userData = {}
    userData['username'] = username
    userData['password'] = password
    userData['prkZpk'] = int(prkZpk, 16)
    userData['pukZpk'] = pukZpk
    userData['alpha'] = alpha
    userData['prkRsa'] = prkRsa
    userData['pukRsa'] = pukRsa
    userData = json.dumps(userData, indent=4)

    f = open("userData.json", "w")
    f.write(userData)
    print("\nYour account has been created successfully!")


def clientLogin(key, clientSock):
    """
    Function to login on the client side
    key: the secret key used for encryption
    clientSock: the client socket
    """
    isConnected = False
    certificateToVerify = receiveMessage(key, clientSock)
    sendMessage(key, certificateToVerify, clientSock)
    isLegit = receiveMessage(key, clientSock)

    if isLegit == "True":
        username = input("Enter your username: ")
        sendMessage(key, username, clientSock)

        motDePasse = input("Enter your password: ")
        motDePasse = SHA3_256(motDePasse.encode()).hexdigest()
        sendMessage(key, motDePasse, clientSock)

        loginMessage = receiveMessage(key, clientSock)
        print(loginMessage)

        if loginMessage == "Connexion successfull!":
            isConnected = True
            return isConnected  


def fileTransfer(key, socket):
    """
    Function to transfer a file
    key: the secret key used for encryption
    socket: the client socket
    """
    filePath = input("Enter the path to the file: ")
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
    print("HMAC of the file ", fileHmac)

    socket.send(str(len(cipherData)).encode())
    socket.send(fileHmac.encode())
    socket.send(cipherData.encode())

    newFileName = input("Save file as : ")
    sendMessage(key, newFileName, socket)

def retrieveFile(key, socket, userData):
    lenList = receiveMessage(key, socket)
    fileList = []
    for i in range(int(lenList)):
        filenameFromServer = receiveMessage(key, socket)
        fileList.append(filenameFromServer)
    print("Acessible files: "+ str(fileList))
    filename = input("Enter filename to get form the list: ")
    if filename in fileList:
        sendMessage(key, filename, socket)
        fileLen = int(socket.recv(32).decode())
        print(fileLen)
        hmacToVerify = socket.recv(64).decode()
        print(hmacToVerify)
        receivedData = ""
        while len(receivedData) < fileLen:
            receivedData += socket.recv(8192).decode()
        print(receivedData)
        parsedData = blockParser(receivedData)
        plainText = ""
        for i in range(len(parsedData)):
            plainText += decrypt(parsedData[i], key)
        fileHmac = hmac(key, receivedData)
        print(fileHmac)
        if fileHmac == hmacToVerify :
            print("Hmac vérifié")
        else:
            print("Attention, Hmac différent")
        plainText = plainText.replace("[", "")
        plainText = plainText.replace("]", "")
        blocksForFile = plainText.split(", ")
        for i in range(len(blocksForFile)):
            blocksForFile[i] = int(blocksForFile[i])
        toWrite = decrypt_text(blocksForFile, userData['prkRsa'])
        print(toWrite)
        newFileName = input("Save file as : ")
        f = open(newFileName, "w")
        f.write(toWrite)
    else:
        print("filename not in list")
    
    

def clientMode(args):
    """
    Function to run the client mode
    args: the arguments passed to the program
    """
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
            clientSock.close()
            ans = False
        elif choice=="2":
            sendMessage(clientSk, "2", clientSock)
            isConnected = clientLogin(clientSk, clientSock)
            if isConnected:
                with open('userData.json', 'r') as file:
                    userData = json.load(file)
                print(userData['prkRsa'])
                print("Que voulez-vous faire?")
                print("1. Déposer un fichier")
                print("2. Consulter un fihier")
                ans2=input("Votre choix: ")
                if ans2 == "1":
                    sendMessage(clientSk, "1", clientSock)
                    fileTransfer(clientSk, clientSock)
                    clientSock.close()
                    ans = False
                if ans2 == "2":
                    sendMessage(clientSk, "2", clientSock)
                    retrieveFile(clientSk, clientSock, userData)
                    clientSock.close()
                    ans = False
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
            clientSock.close()
            ans = False
        elif choice=="5":
            clientSock.close()
            print("\nAu revoir!")
            ans = False
        else:
            print("\nChoix invalide, veuillez réessayer.")
