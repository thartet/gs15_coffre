def toBitstring(text):
    bitString = ""
    for i in text:
        bitString += format(ord(i.encode("utf-8")), '08b')
        print()
    while len(bitString) < 128:
        bitString += "00000000"
    return bitString

def textParser(textToParse):
    out = [(textToParse[i:i+16]) for i in range(0, len(textToParse), 16)]
    return out

def toText(bitstring):
    plainList= [bitstring[i:i+8] for i in range(0, len(bitstring), 8)]
    while '00000000' in plainList:
        plainList.remove('00000000')
    for i in range(len(plainList)):
        plainList[i] = chr(int(plainList[i], 2))
    plainText ="".join(plainList)
    return plainText


def quadSplit(b128):
    """prend un bit string de 128 bit et retourne une liste de 4
    bitsrings de 32bit, avec le bit le moins significatif en premier."""
    
    if len(b128) != 128:
        raise ValueError("must be 128 bits long, not " + str(len(b128)))
    
    result = []
    for i in range(4):
        result.append(b128[(i*32):(i+1)*32])
    return result

def quadJoin(l4x32):
    """Prend une liste de 4 bitstrings de 32bit and et les retourne comme un bitsting
    de 128bits obtenu en les concaténanat."""

    if len(l4x32) != 4:
        raise ValueError("besoin d'une liste de 4 bitstring" + str(len(l4x32)))

    return l4x32[0] + l4x32[1] + l4x32[2] + l4x32[3]

def octoJoin(l8x8):
    """Prend une liste de 8 bitstrings de 8bit and et les retourne comme un bitsting
    de 64bits obtenu en les concaténanat."""

    if len(l8x8) != 8:
        raise ValueError("besoin d'une liste de 8 bitstring" + str(len(l8x8)))

    return l8x8[0] + l8x8[1] + l8x8[2] + l8x8[3] + l8x8[4] + l8x8[5] + l8x8[6] + l8x8[7]

def biSplit(b128):
    """prend un bit string de 128 bit et retourne une liste de 2
    bitsrings de 64bit, avec le bit le moins significatif en premier."""
    
    if len(b128) != 128:
        raise ValueError("must be 128 bits long, not " + str(len(b128)))
    
    result = []
    for i in range(2):
        result.append(b128[(i*64):(i+1)*64])
    return result

def octoSplit(b64):
    """prend un bit string de 64 bit et retourne une liste de 8
    bitsrings de 8bit, avec le bit le moins significatif en premier."""
    
    if len(b64) != 64:
        raise ValueError("must be 128 bits long, not " + str(len(b64)))
    
    result = []
    for i in range(8):
        result.append(b64[(i*8):(i+1)*8])
    return result

Masks = [(1 << i) - 1 for i in range(65)]

def rol(value, left, bits):
    """
    Circularly rotate 'value' to the left,
    treating it as a quantity of the given size in bits.
    """
    top = value >> (bits - left)
    bot = (value & Masks[bits - left]) << left
    return bot | top


def ror(value, right, bits):
    """
    Circularly rotate 'value' to the right,
    treating it as a quantity of the given size in bits.
    """
    top = value >> right
    bot = (value & Masks[right]) << (bits - right)
    return bot | top

def leftShift (num, shift):
    mask = 2**32 -1
    return (num << shift) & mask

def reverseBits(n, bitSize):
    result = 0
    for i in range(bitSize):
        if n & (1 << i):
            result |= 1 << (bitSize - 1 - i)
    return result
