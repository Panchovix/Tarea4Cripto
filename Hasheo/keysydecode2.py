from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii
from contextlib import redirect_stdout


curve = registry.get_curve('brainpoolP256r1')
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext
    
def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext
    
def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()
    
import hasheo2
encryptedMsg = hasheo2.encryptedMsg
decryptedMsg = decrypt_ECC(encryptedMsg, privKey)

with open('outdecrypted2.txt', 'w') as f:
    with redirect_stdout(f):
        print("decrypted msg:", decryptedMsg,'\n')