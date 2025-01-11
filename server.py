import socket
from DiffieHelman import *
from Cobra import *
import json
import rsa
from certificats import *

#fonction permettant de créer un compte côté serveur
#à faire: modifier la fonction pour vérifier que deux compte n'ont pas le même nom d'utilisateur
def create_account(key, connecSock):
    listUser = []
    with open("serverData.json") as file:
        listUser = json.load(file)
    username = reciveMessage(key, connecSock)
    password = reciveMessage(key, connecSock)
    pukZpk = reciveMessage(key, connecSock)
    alpha = reciveMessage(key, connecSock)
    pukRsaToParse = reciveMessage(key, connecSock)
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


#fonction permettant de se connecter à un compte côté serveur
#à faire: modifier la fonction pour vérifier différement les mots de passe, exemple comparaison de hash
#à faire: faire retourner la fonction vers d'autre option pour l'utilisateur: consulter/déposer des fichiers
def login(key, connecSock):
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
    certificateToVerify = eval(reciveMessage(key, connecSock))
    isLegit = ca.verify_certificate(certificateToVerify, ca_public_key)
    sendMessage(key, str(isLegit), connecSock)
    if isLegit:
        username = reciveMessage(key, connecSock)
        motDePasse = reciveMessage(key, connecSock)
        with open("serverData.json", "r") as f:
            serverData = json.load(f)
        loginDict = getDictionary(username, serverData)
        if loginDict is False:
            sendMessage(key, "Identifiant introuvable", connecSock)
            connecSock.close()
        elif motDePasse != loginDict['password']:
            sendMessage(key, "Mot de passe Incorrect", connecSock)
            connecSock.close()
        else:
            sendMessage(key, "Connection accepte", connecSock)
            return loginDict


def getDictionary(username, serverData):
    for dict in serverData:
        if username in dict['username'] :
            return dict

def recieveFile(key, socket, userData):
    fileLen = int(socket.recv(32).decode())
    print(fileLen)
    hmacToVerify = socket.recv(64).decode()
    print(hmacToVerify)
    recieveData=""
    while len(recieveData)<fileLen:
        recieveData += socket.recv(8192).decode()
    print(recieveData)
    parsedData = blockParser(recieveData)
    plainText = ""
    for i in range(len(parsedData)):
        plainText += decrypt(parsedData[i], key)
    fileHmac = hmac(key, recieveData)
    print(fileHmac)
    if fileHmac == hmacToVerify :
        print("Hmac vérifié")
    else:
        print("Attention, Hmac différent")
    blocksForFile = rsa.encrypt_text(plainText, tuple(userData['pukRsa']))
    toWrite = ""
    for i in range(len(blocksForFile)):
        toWrite += str(blocksForFile[i])
    newFileName = reciveMessage(key, socket)
    f = open(newFileName, "w")
    f.write(toWrite)

#fonction décrivant le comportement du programme en mode serveur
#à faire: ajouter d'autre options
def serverMode(args):
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostname = socket.gethostname()
    serverIP = socket.gethostbyname(hostname)
    serverPort = args.port
    socketAddr = (serverIP, serverPort)
    serverSock.bind(socketAddr)
    serverSock.listen(1)
    while True:
        print("Le serveur {} attend une connection sur le port {}".format(serverIP, serverPort))
        connecSock, addr = serverSock.accept()
        serverPuk, serverPrk = genPublicAndPrivateKey(serverSock.getsockname()[0])
        recievedData = connecSock.recv(8192)
        clientPuk = int(recievedData.decode())
        connecSock.send(str(serverPuk).encode())
        serverSk = genSecretKey(clientPuk, serverPrk)
        choice =reciveMessage(serverSk, connecSock)
        print("{} octet reçu de {}:{}".format(len(recievedData), addr, connecSock.getsockname()[1]))
        print("Serveur client:", connecSock.getpeername(), "\nAddresse serveur:", connecSock.getsockname())
        if choice == "1":
            create_account(serverSk, connecSock)
        elif choice == "2":
            userData = login(serverSk, connecSock)
            choice2 = reciveMessage(serverSk, connecSock)
            if choice2 == "1":
                recieveFile(serverSk, connecSock, userData)

            