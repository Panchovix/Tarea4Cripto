from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii
import time
from contextlib import redirect_stdout

#start_time = time.time()

def hashear_SHAKE_hash(string, encoding='utf-8'):
    shake_hasher = hashlib.shake_256()
    shake_hasher.update(string.encode(encoding))
    return shake_hasher.hexdigest(32)

with open("C:\\Users\\Pancho\\Desktop\\Tarea 4 cripto\\Hasheo nuevo\\crackeado4d2plain.txt") as e, open("output4.txt", "w") as f:
    for line in e:
        hasheado = hashear_SHAKE_hash(line)
        with redirect_stdout(f):
            print(hasheado)
            
            
def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)


def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)


msg = open('output1.txt', 'rb').read()
#print("original msg:", msg)
import keysydecode4
pubKey = keysydecode4.pubKey

encryptedMsg = encrypt_ECC(msg, pubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'nonce': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2]),
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}

with open('outencrypted4.txt', 'w') as f:
    with redirect_stdout(f):
        print("encrypted msg:", encryptedMsgObj,'\n')

#seconds = time.time() - start_time
#print('Tiempo de ejecución:', time.strftime("%H:%M:%S",time.gmtime(seconds)))

