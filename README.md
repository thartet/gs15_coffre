This repository contains the code that we produced during the automn semester at the UTT for the GS15 course. You can find the requirements in the file **Projet_A24_coffreFort.pdf**

## Usage
### Cloning the repository
You have to clone the repository at first and move into the repository that you just cloned

```bash
git clone https://github.com/thartet/gs15_coffre.git
cd gs15_coffre
```
### How to use the program
The program uses sockets and you have to run two instances on two different terminals.

The first instance is the server instance, that can be run using the command :

``` bash
python3 main.py -s
> The server 127.0.1.1 is waiting for a connexion on port 9999
```
Once you run it, you get an ip adress and a port, here, the ip address is 127.0.1.1.

We have to run the second instance, the client instance, using the command :
``` bash
python3 main.py -c -ip <ip_given_above>
```

Once connected on the client instance, we are faced with the menu that gives us different options :

>Hello Master T! What would you like to do today?
>
>1. Create your account
>2. Log in
>3. Test encryption functions
>4. Generate an RSA key pair
>5. Quit

Once we login, we face a second menu where we can choose to transfer a new file, to retrieve one, or to disconnect.

In the 3rd option, "test encryption functions", we can also test multiple functions.
> Which cryptographic function would you like to test?
> 1. Cobra
> 2. Diffie-Helman
> 3. SHA3-256
> 4. HMAC SHA-256
> 5. RSA
> 6. SHA-256
> 7. ZPK

The 4th option is used to generate a pair of RSA keys that can be found in the .keys_client folder.

