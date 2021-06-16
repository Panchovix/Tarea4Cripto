from tinyec import registry #librería para realizar operaciones aritméticas en curvas elípticas
from Crypto.Cipher import AES # Se usará AES en conjunto de ECC + ECDH para todo el proceso
import hashlib, secrets, binascii # hashlib contiene la información de ECC y SHAKE256, secrets para generación aleatoria
# y binascii para usar las operaciones de ascii
from contextlib import redirect_stdout # librería para pasar outputs a un archivo de texto
import socket

HOST = '127.0.0.1'  # La IP del servidor a conectar
PORT = 65432        # El puerto del servidor


def hashear_SHAKE_hash(string, encoding='utf-8'): #operación para hashear los archivos con SHAKE 256
    shake_hasher = hashlib.shake_256() # se define que se usará SHAKE256 en hashlib
    shake_hasher.update(string.encode(encoding)) #se hace un encode para que no existan problemas en los datos 
    return shake_hasher.hexdigest(32) #se retorna el hasheo, por string, con párametro 32 de largo en SHAKE256
    
def encrypt_AES_GCM(msg, secretKey): # se crea la función que usa AES por si solo
    aesCipher = AES.new(secretKey, AES.MODE_GCM) #Modo GCM de AES 
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg) #parametros para encriptar y hacer digest, del mensaje
    return (ciphertext, aesCipher.nonce, authTag) #retorna los parametros


def ecc_point_to_256_bit_key(point): #función para transformar los puntos de la curva ecc en una llave de 256 bits
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big')) #esta se realiza mediante sha256
    sha.update(int.to_bytes(point.y, 32, 'big')) #y de largo 32
    return sha.digest() #retorna el digest con respecto al sha256

def encrypt_ECC(msg, pubKey): #función para encriptar con ECC + ECDH + AES, usando la llave pública
    ciphertextPrivKey = secrets.randbelow(curve.field.n) # toma un punto aleatorio de la curva y cifra la llave privada
    sharedECCKey = ciphertextPrivKey * pubKey # la llave ECC compartida se crea al multiplicar la llave cifrada privada por la publica
    secretKey = ecc_point_to_256_bit_key(sharedECCKey) # pasa la llave secreta a 256 bit en conjunto con el punto de la llave compartida de ECC
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey) #se le asignan los parametros de ECC a AES
    ciphertextPubKey = ciphertextPrivKey * curve.g # se cifra la llave publica con la llave privada por un punto de la curva P256 y ECDH
    return (ciphertext, nonce, authTag, ciphertextPubKey) #devuelve los valores necesarios y cifrados
    
def compress_point(point):
  return hex(point.x) + hex(point.y % 2)[2:]


curve = registry.get_curve('brainpoolP256r1') #curva a utilizar en ECC, en este caso la P256
pubKey = None
opcion2 = None
msg = None
encryptedMsg = None
encryptedMsgObj = None
hasheado = None
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
clientSocket.connect((HOST, PORT))
opcion = int(input("ingrese 1 para generar una key publica y privada en el servidor, y recibir la llave publica para encriptar, o ingrese 2 para desencriptar si ya realizo el primer paso"))
#se envía un 1, para dar la señal de que el otro código de python cree las llaves, y este le mande la llave pública, o 2 para pedir al servidor descifrar la información
if (opcion == 1):
    clientSocket.send(bytes(opcion))
    pubKey = open('keypub11.txt').read()
    with open("C:\\Users\\Pancho\\Desktop\\Tarea 4 cripto\\Hasheo nuevo\\crackeado1d2plain.txt") as e, open("output1.txt", "w") as f: # abre el archivo con las contraseñas en texto plano para hashearlas, y así también
# se crea un archivo con un output con el hash guardado
        for line in e: #para cada linea del texto plano
            hasheado = hashear_SHAKE_hash(line) #se aplica SHAKE256
            with redirect_stdout(f): #para cada linea nueva que se va creando
                print(hasheado) #se crea el archivo completo con cada linea hasheada
    print ("Mensaje correctamente hasheado con shake_256")
            
    msg = open('output1.txt', 'rb').read() #lee el mensaje contenido en output creado anteriormente luego del SHAKE256
    encryptedMsg = encrypt_ECC(msg, pubKey) # se crea el mensaje encriptado usando la función ECC con la llave publica
    encryptedMsgObj = {
        'ciphertext': binascii.hexlify(encryptedMsg[0]),
        'nonce': binascii.hexlify(encryptedMsg[1]),
        'authTag': binascii.hexlify(encryptedMsg[2]),
        'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
        }
    with open('outencrypted1.txt', 'w') as f: #se crea el archivo encriptado
        with redirect_stdout(f):
            print("encrypted msg:", encryptedMsgObj,'\n')
    print ("mensaje encriptado",'\n')
    opcion2 = int(input("Ingrese 2 si quiere enviar el mensaje al segundo archivo para desencriptar, o ingrese cualquier otro valor para terminar el programa", '\n'))
    if opcion2 == 2:
        clientSocket.send(bytes(opcion2))
    else:
        print ("opción no valida")

elif (opcion == 2):
    clientSocket.send(bytes(opcion))
else:
    print ("opcion no valida")

#import time / se usó para tomar los tiempos de ejecución de los hash
#start_time = time.time()




            

            




#print("original msg:", msg)



#crea los parametros con respecto a la encriptación realizada 


#seconds = time.time() - start_time
#print('Tiempo de ejecución:', time.strftime("%H:%M:%S",time.gmtime(seconds)))

