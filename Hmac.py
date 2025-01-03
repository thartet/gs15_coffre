from sha256 import *

opad = bytes((x ^ 0x5C) for x in range(256))
ipad = bytes((x ^ 0x36) for x in range(256))

def hmac (key, message):
    intKey = int(key, 2)
    keyOpad = intKey ^ int.from_bytes(opad, 'big')
    keyIpad = intKey ^ int.from_bytes(ipad, 'big')
    firstToHash = str(keyIpad) + message
    firstHash = sha256(firstToHash.encode()).hex()
    secondToHash = str(keyOpad) + firstHash
    hmac = sha256(secondToHash.encode()).hex()
    return hmac



