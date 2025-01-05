import socket
from DiffieHelman import *
from Cobra import *

#fonction permettant de créer un compte côté serveur
#à faire: modifier la fonction pour vérifier que deux compte n'ont pas le même nom d'utilisateur
def create_account(connecSock):
    receivedData = connecSock.recv(8192)
    username = receivedData.decode()
    receivedData = connecSock.recv(8192)
    password = receivedData.decode()
    with open('users.txt', 'a') as file:
        file.write(username + ' ' + password + '\n')
    connecSock.send("Votre compte a été créé avec succès!".encode())

#fonction permettant de se connecter à un compte côté serveur
#à faire: modifier la fonction pour vérifier différement les mots de passe, exemple comparaison de hash
#à faire: faire retourner la fonction vers d'autre option pour l'utilisateur: consulter/déposer des fichiers
def login(connecSock):
    receivedData = connecSock.recv(8192)
    username = str(receivedData.decode())
    receivedData = connecSock.recv(8192)
    password = str(receivedData.decode())
    
    with open('users.txt', 'r') as file:
        for line in file:
            if username in line and password in line:
                connecSock.send("Connexion réussie!".encode())
                return 0
    connecSock.send("Nom d'utilisateur ou mot de passe incorrect.".encode())

def recieveFile(key, socket):
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
    newFileName = reciveMessage(key, socket)
    f = open(newFileName, "w")
    f.write(plainText)

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
        recievedData = connecSock.recv(8192)
        print("{} octet reçu de {}:{}".format(len(recievedData), addr, connecSock.getsockname()[1]))
        print("Serveur client:", connecSock.getpeername(), "\nAddresse serveur:", connecSock.getsockname())
        if recievedData.decode() == "1":
            create_account(connecSock)
        elif recievedData.decode() == "2":
            login(connecSock)