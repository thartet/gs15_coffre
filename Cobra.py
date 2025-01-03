import random
import socket
from Hmac import *
from helpFunction import * 
from hash import *
#représentation du nombre d'or sur 32 bit, et r le nombre de permutation
phi = 0b00111111110011110001101110111101
r =32

#Tables de permutation Initial et Final de Sepent
IPTable = [
    0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
    4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
    8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
    12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
    16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
    20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
    24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
    28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
    ]
FPTable = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
    2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
    66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
    3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
    67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
 ]
#SBox de SERPENT, pensez à les remplacer par un nouvel table
SBoxDecimalTable = [
	[ 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 ], # S0
	[15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 ], # S1
	[ 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 ], # S2
	[ 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 ], # S3
	[ 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 ], # S4
	[15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 ], # S5
	[ 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 ], # S6
	[ 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 ], # S7
    ] 

#Applique la permutation sur une liste de 128 élément
#'permutationTable' au bitstring de 128 bits 'input' et retourne
#un bitstring de 128 bits comme résultat.
def applyPermutation(permutationTable, input):
    if len(input) != len(permutationTable):
        raise ValueError("taille de l'input (%d) n'est pas la même que la taille de la table de permutation (%d)"% (len(input), len(permutationTable)))
    result = ""
    for i in range(len(permutationTable)):
        result = result + input[permutationTable[i]]
    return result

SBoxBitstring = []
SBoxBitstringInverse = []
for line in SBoxDecimalTable:
    dict = {}
    inverseDict = {}
    for i in range(len(line)):
        index = format(i, '04b')
        value = format(line[i], '04b')
        dict[index] = value
        inverseDict[value] = index
    SBoxBitstring.append(dict)
    SBoxBitstringInverse.append(inverseDict)

def S(box, input):
    return SBoxBitstring[box%8][input]

def SInverse(box, output):
    """Apply S-box number 'box' in reverse to 4-bit bitstring 'output' and
    return a 4-bit bitstring (the input) as the result."""

    return SBoxBitstringInverse[box%8][output]

#cette fonction permet peut-importe la clé d'origine de l'étendre à une clé de 256 bit, 
# elle retourne un tableau de 8 blocs de 32 bits de la clé d'origine
def initializeKey (sessionKey):
    K=[]
    while len(sessionKey)<256:
        sessionKey.append(0)
    for i in range(8):
        K.append(sessionKey[i*32:32+i*32])
    return K

#cette fonction permet d'itéré l'expansion de la clé, à partir des 8 sous blocs de la fonction initializeKey
# On génère un tableau de 132 sous clé en apliquant une fonction de récurence 
def keyExpansion(K):
    w=[]
    for i in range (8):
        w.append(int(K[i], 2))
    for i in range (8,132):
        w.append(rol(w[i-8]^w[i-5]^w[i-3]^w[i-1]^phi^i, 11, 32))
    for i in range (len(w)):
        w[i] = format(w[i], '032b') 
    return w

def SBoxTransform (w):
    k = {}
    for i in range(r+1):
        whichSBox = (r + 3 - i) % r
        k[0+4*i] = ""
        k[1+4*i] = ""
        k[2+4*i] = ""
        k[3+4*i] = ""
        for j in range(32): 
            input = w[0+4*i][j] + w[1+4*i][j] + w[2+4*i][j] + w[3+4*i][j]
            output = S(whichSBox, input)
            for l in range(4):
                k[l+4*i] = k[l+4*i] + output[l]
    K = []
    for i in range(33):
        K.append(k[4*i] + k[4*i+1] + k[4*i+2] + k[4*i+3])
    #D'après la documentation de l'algorithme on applique la permutation initiale pour placer les éléments de K[i] pour les placer dans la bonne colone
    KHat = []
    for i in range(33):
        KHat.append(applyPermutation(IPTable,K[i]))
    return KHat, K

#Cette fonction permet de générer une clé de session aléatoire dans un bitarray
def genSessionKey():
    sessionKey=''
    while True:
        keySize=int(input("Quelle taille de clé voulez-vous générer? (128, 192 ou 256): "))
        if keySize == 128:
            sessionKey=format(random.getrandbits(128), '0128b')
            break
        elif keySize == 192:
            sessionKey=format(random.getrandbits(192), '0192b')
            break
        elif keySize == 256:
            sessionKey=format(random.getrandbits(256), '0256b')
            break
        else:
            print("Wrong key size")
    return sessionKey

def SBitslice(box, words):
    """Prends 'words', une liste de 4 bitstrings de 32bits, word le moins significatif en premier. 
    retourne une liste similaire de 4 bitstrings de 32bits obtenu par: 
    Pour chaque bit positionné de 0 à 31, application de la Sbox numéro 'box'
    aux bits d'input venant de leur position actuel dans chaque
    items dans 'words'; et met les 4 bits en output dans les positions correspondates
    dans les words en output."""

    result = ["", "", "", ""]
    for i in range(32):
        quad = S(box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result

def SBitsliceInverse(box, words):
    """Take 'words', a list of 4 32-bit bitstrings, least significant word
    first. Return a similar list of 4 32-bit bitstrings obtained as
    follows. For each bit position from 0 to 31, apply S-box number 'box'
    in reverse to the 4 output bits coming from the current position in
    each of the items in the supplied 'words'; and put the 4 input bits in
    the corresponding positions in the returned words."""

    result = ["", "", "", ""]
    for i in range(32): # ideally in parallel
        quad = SInverse(
            box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result


def F(Ki, R):
    Ri = octoSplit(R)
    for i in range (len(Ri)):
        Ri[i] = reverseBits(int(Ri[i], 2), 8)
        Ri[i]= pow(Ri[i]+1, -1, 257) -1
        Ri[i] = format(Ri[i], '08b')
    permTable = [56, 38, 60, 33, 20, 9, 36, 58, 26, 10, 49, 61, 14, 8, 24, 62, 52, 12, 43, 59, 54, 18, 44, 11, 57, 31, 27, 53, 34, 39, 13, 51, 29, 28, 0, 48, 6, 55, 17, 35, 2, 16, 32, 37, 1, 47, 4, 15, 41, 42, 45, 63, 3, 25, 5, 21, 22, 46, 30, 50, 40, 7, 19, 23]
    Ri = applyPermutation(permTable, octoJoin(Ri))
    Ri = octoSplit(Ri)
    for i in range (len(Ri)):
        random.seed(int(Ri[i], 2))
        Ri[i] = format(random.getrandbits(8), '08b')
    derivedKey = SHA3_256(int(Ki, 2).to_bytes(16, 'big')).hexdigest()
    derivedKey = format(int(derivedKey, 16), '0256b')
    Ri = octoJoin(Ri)
    result = ''.join(str(int(R[i]) ^ int(derivedKey[i])) for i in range(64))
    return result


def laFeistelDeRere(Si, Ki):
    L, R = biSplit(Si)
    for i in range (3):
        Li = R
        Ri = int(L, 2) ^ int(F(Ki, R), 2)
        L = Li
        R = format(Ri, '064b')
    return L+R

def laFeistelDeRereInverse(Si, Ki):
    L, R = biSplit(Si)
    for i in range (3):
        Ri = L
        Li = int(R, 2) ^ int(F(Ki, L), 2)
        R = Ri
        L = format(Li, '064b')
    return L+R
    
def LTBitslice(X):
    """Applique la version basé sur les équations de la transformation linéaire
    à 'X', une liste de 4 bitstrings de 32 bits, bitstring le moins signifiant en premier,
    et retourne une autre liste de 4bitstrings de 32bits comme résultat."""
    X[0] = rol(int(X[0], 2), 13, 32)
    X[2] = rol(int(X[2], 2), 3, 32)
    X[1] = int(X[1], 2) ^ X[0] ^ X[2]
    X[3] = int(X[3], 2) ^ X[2] ^ leftShift(X[0], 3)
    X[1] = rol(X[1], 1, 32)
    X[3] = rol(X[3], 7, 32)
    X[0] = X[0] ^ X[1] ^ X[3]
    X[2] = X[2] ^ X[3] ^ leftShift(X[1], 7)
    X[0] = rol(X[0], 5, 32)
    X[2] = rol(X[2], 22, 32)
    X[0] = format(X[0], '032b')
    X[1] = format(X[1], '032b')
    X[2] = format(X[2], '032b')
    X[3] = format(X[3], '032b')
    return X

def LTBitsliceInverse(X):
    """Apply, in reverse, the equations-based version of the linear
    transformation to 'X', a list of 4 32-bit bitstrings, least significant
    bitstring first, and return another list of 4 32-bit bitstrings as the
    result."""
    X[2] = ror(int(X[2], 2), 22, 32)
    X[0] = ror(int(X[0], 2), 5, 32)
    X[2] = X[2] ^ int(X[3], 2) ^ leftShift(int(X[1], 2), 7)
    X[0] = X[0] ^ int(X[1], 2) ^ int(X[3], 2)
    X[3] = ror(int(X[3], 2), 7, 32)
    X[1] = ror(int(X[1], 2), 1, 32)
    X[3] = X[3] ^ X[2] ^ leftShift(X[0], 3)
    X[1] = X[1] ^ X[0] ^ X[2]
    X[2] = ror(X[2], 3, 32)
    X[0] = ror(X[0], 13, 32)
    X[0] = format(X[0], '032b')
    X[1] = format(X[1], '032b')
    X[2] = format(X[2], '032b')
    X[3] = format(X[3], '032b')
    return X


def round(i, Bi, Ki):
    xored = int(Bi, 2) ^ int(Ki, 2)
    xored = format(xored, '0128b')
    Si = SBitslice(i, quadSplit(xored))
    Si = quadJoin(Si)
    LFDR = laFeistelDeRere(Si, Ki)
    if i == r-1:
        biPlus1 = int(LFDR, 2) ^ int(Ki[r], 2)
        biPlus1 = format(biPlus1, '0128b')
    else:
        biPlus1 = quadJoin(LTBitslice(quadSplit(LFDR)))
    return biPlus1

def invRound(i, Biplus1, Ki):
    if i == r-1:
        Si = int(Biplus1, 2) ^ int(Ki[r], 2)
        Si = format(Si, '0128b')
    else:
        Si = quadJoin(LTBitsliceInverse(quadSplit(Biplus1)))
    LFDRInverse = laFeistelDeRereInverse(Si, Ki)
    xoredInverse = SBitsliceInverse(i, quadSplit(LFDRInverse))
    xoredInverse = quadJoin(xoredInverse)
    Bi = int(xoredInverse, 2) ^ int(Ki, 2)
    Bi = format(Bi, '0128b')
    return Bi    

def encrypt(plainText, key):
    bitText = toBitstring(plainText)
    genKey = initializeKey(key)
    w = keyExpansion (genKey)
    KHat, K = SBoxTransform(w)
    B=applyPermutation(IPTable, bitText)
    for i in range(r):
        B = round(i, B, KHat[i])
    cipherText = applyPermutation(FPTable, B)
    return cipherText

def decrypt(cipherText, key):
    genKey=initializeKey(key)
    w = keyExpansion (genKey)
    KHat, K = SBoxTransform(w)
    B = applyPermutation(IPTable, cipherText)
    for i in range (r-1, -1, -1):
        B = invRound(i, B, KHat[i])
    plainText = applyPermutation(FPTable, B)
    plainText = toText(plainText)
    return plainText

def sendMessage(key, message, socket):
    messageBlocks = textParser(message)
    messageHmac = hmac(key, message)
    print("HMAC du message: ", messageHmac)
    socket.send(str(len(messageBlocks)).encode())
    cipherText = []
    for i in range(len(messageBlocks)):
        cipherBlock = encrypt(messageBlocks[i], key)
        cipherText.append(cipherBlock)
        socket.send(str(cipherBlock).encode())
    print("Texte chiffré: ", cipherText)
    socket.send(messageHmac.encode())
    

def reciveMessage(key, socket):
    recivedData = socket.recv(8192)
    nbBlocks = int(recivedData.decode())
    message = ""
    for i in range(nbBlocks):
        recivedData = socket.recv(128)
        plainText = decrypt(recivedData.decode(), key)
        message += plainText
    recivedData = socket.recv(256)
    recivedHmac = recivedData.decode()
    messageHmac = hmac(key, message)
    print(messageHmac)
    if messageHmac == recivedHmac :
        print("Hmac vérifié")
    else:
        print("Attention, Hmac différent")
    return message
