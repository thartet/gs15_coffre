
#représentation du nombre d'or sur 32 bit
phi = 0b00111111110011110001101110111101
#cette fonction permet peut-importe la clé d'origine de l'étendre à une clé de 256 bit, 
# elle retourne un tableau de 8 blocs de 32 bits de la clé d'origine
def initializeKey (sessionKey):
    K=[]
    while len(sessionKey)<256:
        sessionKey.append(0)
    for i in range(8):
        K.append(sessionKey[i*32:32+i*32])
    return K
#Cette fonction permet de faire une rotation circulaire gauche pour un entier donné
def circularLeftShift(num, shift, nbBit):
    return ((num<<shift) % (1<<nbBit) | (num >> (nbBit-shift)))
#cette fonction permet d'itéré l'expansion de la clé, à partir des 8 sous blocs de la fonction initializeKey
# On génère un tableau de 132 sous clé en apliquant une fonction de récurence 
def keyExpansion(K):
    w=[]
    for i in range (8):
        w.append(int(K[i], 2))
    for i in range (8,132):
        w.append(circularLeftShift(w[i-8]^w[i-5]^w[i-3]^w[i-1]^phi^i, 11, 32))   
    return w