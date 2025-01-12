import socket
from DiffieHelman import *
from Cobra import *
import json
import rsa
from certificats import *


def create_account(key, connecSock):
    """
    Function to create an account on the server side
    key: the secret key used for encryption
    connecSock: the connection socket
    """
    listUser = []
    with open("serverData.json") as file:
        listUser = json.load(file)
    username = receiveMessage(key, connecSock)
    password = receiveMessage(key, connecSock)
    pukZpk = receiveMessage(key, connecSock)
    alpha = receiveMessage(key, connecSock)
    pukRsaToParse = receiveMessage(key, connecSock)
    pukRsaToParse = pukRsaToParse.replace("(", "")
    pukRsaToParse = pukRsaToParse.replace(")", "")
    pukRsa = tuple(map(int, pukRsaToParse.split(', ')))
    userData = {}
    userData['username'] = username
    userData['password'] = password
    userData['pukZpk'] = pukZpk
    userData['alpha'] = alpha
    userData['pukRsa'] = pukRsa
    userData['fileList'] = []
    listUser.append(userData)
    with open ("serverData.json", "w") as jsonFile:
        json.dump(listUser, jsonFile, indent=4)


def login(key, connecSock):
    """
    Function to login on the server side
    key: the secret key used for encryption
    connecSock: the connection socket
    """
    with open('.keys_server/rsa.pub', 'rb') as pub_file:
        pub = pub_file.read()
        tab = pub.split(b'\n')
        pub = (int(tab[0].decode()), int(tab[1].decode()))
        print(pub)

    with open('.keys_server/rsa', 'rb') as priv_file:
        priv = priv_file.read()
        tab = priv.split(b'\n')
        priv = (int(tab[0].decode()), int(tab[1].decode()))
        print(priv)

    ca_private_key = priv
    ca_public_key = pub
    ca = SimpleCA(ca_private_key)
    
    # Issuing a certificate
    usernameCert = "Serveur"
    public_key = pub
    certificate = ca.issue_certificate(usernameCert, public_key)
    with open ("certificat.pem", "w") as f:
        f.write(json.dumps(certificate))
    sendMessage(key, str(certificate), connecSock)
    certificateToVerify = eval(receiveMessage(key, connecSock))
    isLegit = ca.verify_certificate(certificateToVerify, ca_public_key)
    sendMessage(key, str(isLegit), connecSock)
    if isLegit:
        username = receiveMessage(key, connecSock)
        motDePasse = receiveMessage(key, connecSock)
        with open("serverData.json", "r") as f:
            serverData = json.load(f)
        loginDict = getDictionary(username, serverData)
        if loginDict is False:
            sendMessage(key, "Incorrect login", connecSock)
            connecSock.close()
        elif motDePasse != loginDict['password']:
            sendMessage(key, "Incorrect password", connecSock)
            connecSock.close()
        else:
            sendMessage(key, "Connexion successfull!", connecSock)
            return loginDict


def getDictionary(username, serverData):
    """
    Function to get the dictionary of a user
    username: the username of the user
    serverData: the data of the server
    returns the dictionary of the user
    """
    for dict in serverData:
        if username in dict['username'] :
            return dict

def receiveFile(key, socket, userData):
    """
    Function to receive a file
    key : the secret key used for encryption
    socket : the socket
    userData : the data of the user
    """
    fileLen = int(socket.recv(4).decode())
    hmacToVerify = socket.recv(64).decode()
    print(hmacToVerify)
    receiveData=""
    while len(receiveData)<fileLen:
        receiveData += socket.recv(8192).decode()
    print(receiveData)
    parsedData = blockParser(receiveData)
    plainText = ""
    for i in range(len(parsedData)):
        plainText += decrypt(parsedData[i], key)
    fileHmac = hmac(key, receiveData)
    print(fileHmac)
    if fileHmac == hmacToVerify :
        print("Hmac verified")
    else:
        print("Warning, different Hmac")
    blocksForFile = rsa.encrypt_text(plainText, tuple(userData['pukRsa']))
    newFileName = receiveMessage(key, socket)
    f = open(newFileName, "w")
    f.write(str(blocksForFile))
    addFile(userData, newFileName)


def addFile(userData, fileName):
    """
    Function to add a file to the user data
    userData : the data of the user
    fileName : the name of the file
    """
    listUser = []
    userData['fileList'].append(fileName)
    with open("serverData.json") as file:
        listUser = json.load(file)
    file.close()

    for user in list(listUser):
        if str(userData['username']) == user['username']:
            listUser.remove(user)

    listUser.append(userData)
    with open ("serverData.json", "w") as jsonFile:
        json.dump(listUser, jsonFile, indent=4)


def sendFile(key, socket, userData):
    """
    Function to send a file
    key : the secret key used for encryption
    socket : the socket
    userData : the data of the user
    """
    fileList = userData['fileList']
    sendMessage(key, str(len(fileList)), socket)
    for i in range(len(fileList)):
        sendMessage(key, fileList[i], socket)
    filename = receiveMessage(key, socket)
    f = open(filename, "r")
    data = f.read()
    textBlocks = textParser(data)
    cipherData = ""
    for i in range(len(textBlocks)):
        cipherData += encrypt(textBlocks[i], key)
    print(cipherData)
    print(len(cipherData))

    fileHmac = hmac(key, cipherData)
    print("HMAC of the file ", fileHmac)
    socket.send(str(len(cipherData)).encode())
    socket.send(fileHmac.encode())
    socket.send(cipherData.encode())


def serverMode(args):
    """
    Function to describe the behavior of the program in server mode
    args: the arguments passed to the program
    """
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostname = socket.gethostname()
    serverIP = socket.gethostbyname(hostname)
    serverPort = args.port
    socketAddr = (serverIP, serverPort)
    serverSock.bind(socketAddr)
    serverSock.listen(1)
    
    while True:
        print("The server {} is waiting for a connexion on port {}".format(serverIP, serverPort))
        connecSock, addr = serverSock.accept()
        serverPuk, serverPrk = genPublicAndPrivateKey(serverSock.getsockname()[0])
        receivedData = connecSock.recv(8192)
        clientPuk = int(receivedData.decode())
        connecSock.send(str(serverPuk).encode())
        serverSk = genSecretKey(clientPuk, serverPrk)
        choice = receiveMessage(serverSk, connecSock)
        print("{} bytes received from {}:{}".format(len(receivedData), addr, connecSock.getsockname()[1]))
        print("Client connected from:", connecSock.getpeername(), "\nServer address:", connecSock.getsockname())
        
        if choice == "1":
            create_account(serverSk, connecSock)

        elif choice == "2":
            userData = login(serverSk, connecSock)
            choice2 = receiveMessage(serverSk, connecSock)

            if choice2 == "1":
                receiveFile(serverSk, connecSock, userData)
                
            elif choice2 == "2":
                sendFile(serverSk, connecSock, userData)

            