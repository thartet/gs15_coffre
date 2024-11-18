import socket

#fonction permettant de créer un compte côté client
#à faire: trouver un moyen de transmettre le mot de passe de manière non-clairs
def clientCreateAccount(clientSock):
    username = input("Entrez votre nom d'utilisateur: ")
    clientSock.send(username.encode())
    password = input("Entrez votre mot de passe: ")
    clientSock.send(password.encode())
    recievedData = clientSock.recv(8192)
    print(recievedData.decode())

#fonction permettant de se connecter à un compte côté client
#à faire: trouver un moyen de transmettre le mot de passe de manière non-clairs
def clientLogin(clientSock):
    username = input("Entrez votre nom d'utilisateur: ")
    clientSock.send(username.encode())
    password = input("Entrez votre mot de passe: ")
    clientSock.send(password.encode())
    recievedData = clientSock.recv(8192)
    print(recievedData.decode())

#fonction du programme pour le faire fonctionner en mode Client
#à faire: rajouter des options
def clientMode(args):
    clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketAddr= (args.ipAddress,args.port)
    clientSock.connect(socketAddr)
    ans=True
    while ans:
        print("Bonjour ô maître T ! Que souhaitez-vous faire aujourd'hui?")
        print("1. Créer votre compte")
        print("2. Vous connecter")
        print("3. Quitter")

        ans=input("Votre choix: ")
        if ans=="1":
            clientSock.send("1".encode())
            clientCreateAccount(clientSock)
        elif ans=="2":
            clientSock.send("2".encode())
            clientLogin(clientSock)
        elif ans=="3":
            clientSock.close()
            print("\nAu revoir!")
            ans = False
        else:
            print("\nChoix invalide, veuillez réessayer.")
