from tinyec import registry #librería para realizar operaciones aritméticas en curvas elípticas
from Crypto.Cipher import AES # Se usará AES en conjunto de ECC + ECDH para todo el proceso
import hashlib, secrets, binascii # hashlib contiene la información de ECC y SHAKE256, secrets para generación aleatoria
# y binascii para usar las operaciones de ascii
from contextlib import redirect_stdout # librería para pasar outputs a un archivo de texto


curve = registry.get_curve('brainpoolP256r1') #curva a utilizar, P256
privKey = secrets.randbelow(curve.field.n) #se crea la llave privada usando la librería secrets en un punto de la curva
print ("llave privada creada")
pubKey = privKey * curve.g #se crea la llave publica multipicando la privada por un punto de la curva
print ("llave pública creada")

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey): #función para descenrriptar con solo AES
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce) #modo de AES y sus variables, como llave secreta y nonce
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag) # se obtiene el texto plano al descifrar
    return plaintext #retorna el texto plano
    
def decrypt_ECC(encryptedMsg, privKey): #función para descencriptar utilizando ECC, ECDH, AES y la llave privada
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg #se obtiene el mensaje encriptado
    sharedECCKey = privKey * ciphertextPubKey #la llave compartida ECC con la llave privada por la llave cifrada pública
    secretKey = ecc_point_to_256_bit_key(sharedECCKey) #pasa la llave secreta a 256 bit en conjunto con el punto de la llave compartida de ECC
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)#se crea el texto en plano utilizando AES + ECDH
    return plaintext #retorna el texto plano
    
def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()
    
from hasheo1 import encryptedMsg #
decryptedMsg = decrypt_ECC(encryptedMsg, privKey) #el mensaje desencriptado se crea utilizando la función para desencriptar creada ECC, con parametros el mensaje encriptado y la llave privada

with open('outdecrypted1.txt', 'w') as f: #se crea el archivo con el texto desencriptado
    with redirect_stdout(f):
        print("decrypted msg:", decryptedMsg,'\n')
        
print ("mensaje descencriptado")