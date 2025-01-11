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
    userData['alpha'] = alpha
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
    receivedData = clientSock.recv(8192)
    serverPuk = int(receivedData.decode())
    clientSk = genSecretKey(serverPuk, clientPrk)

    ans = True
    while ans:
        print("\nHello Master T! What would you like to do today?")
        print("1. Create your account")
        print("2. Log in")
        print("3. Test encryption functions")
        print("4. Generate an RSA key pair")
        print("5. Quit")

        choice = input("Your choice: ")
        if choice == "1":
            sendMessage(clientSk, "1", clientSock)
            clientCreateAccount(clientSk, clientSock)

        elif choice == "2":
            sendMessage(clientSk, "2", clientSock)
            isConnected = clientLogin(clientSk, clientSock)

            if isConnected:
                print("What would you like to do?")
                print("1. Transfer a file")
                print("2. View your files")
                print("3. Disconnect")

                ans2 = input("Your choice: ")

                if ans2 == "1":
                    sendMessage(clientSk, "1", clientSock)
                    fileTransfer(clientSk, clientSock)
                
                elif ans2 == "2":
                    print("View files")
                    # To be implemented

                elif ans2 == "3":
                    print("Disconnecting...")
                    sendMessage(clientSk, "3", clientSock)
                    clientSock.close()

        elif choice == "3":
            print("Which encryption function would you like to test?")
            print("1. Cobra")
            print("2. Diffie-Helman")
            print("3. SHA3-256")
            print("4. HMAC SHA-256")
            print("5. RSA")
            print("6. SHA-256")
            print("7. ZPK")

            ans2=input("Your choice: ")

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

        elif choice == "4":
            generate_keyfiles()

        elif choice == "5":
            clientSock.close()
            print("\nSee you soon Master!")
            ans = False

        else:
            print("\nInvalid choice. Please try again.")
