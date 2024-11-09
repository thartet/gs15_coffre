def create_account():
    username=input("Entrez votre nom d'utilisateur:")
    password=input("Entrez votre mot de passe:")
    with open('users.txt', 'a') as file:
        file.write(username + ' ' + password + '\n')
    print("Votre compte a été créé avec succès!")

def login():
    username=input("Entrez votre nom d'utilisateur:")
    password=input("Entrez votre mot de passe:")
    with open('users.txt', 'r') as file:
        for line in file:
            if username in line and password in line:
                print("Connexion réussie!")
                return
    print("Nom d'utilisateur ou mot de passe incorrect.")

def main():
    ans=True
    while ans:
        print("Bonjour ô maître T ! Que souhaitez-vous faire aujourd'hui?")
        print("1. Créer votre compte")
        print("2. Vous connecter")
        print("3. Quitter")

        ans=input("Votre choix: ")
        if ans=="1":
            create_account()
        elif ans=="2":
            login()
        elif ans=="3":
            print("\nAu revoir!")
            ans = False
        else:
            print("\nChoix invalide, veuillez réessayer.")

if __name__ == '__main__':
    main()
