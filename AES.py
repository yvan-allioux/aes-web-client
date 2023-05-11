from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_aes(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return cipher.iv, cipher_text

def decrypt_aes(cipher_text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(cipher_text), AES.block_size).decode()
    return plain_text

def generate_key():
    key = get_random_bytes(32)
    key_base64 = base64.b64encode(key).decode()
    return key_base64

def encrypt_aes_base64(plain_text, key_user_input):
    key = base64.b64decode(key_user_input.encode()) # Convertir la clé base64 en octets
    iv, cipher_text = encrypt_aes(plain_text, key)
    final_cipher_text = base64.b64encode(iv + cipher_text).decode()
    return final_cipher_text

def decrypt_aes_base64(encrypted_text, key_user_input):
    key = base64.b64decode(key_user_input.encode()) # Convertir la clé base64 en octets
    iv = base64.b64decode(encrypted_text.encode())[:AES.block_size] # Extraire l'IV
    encrypted_text = base64.b64decode(encrypted_text.encode())[AES.block_size:] # Extraire le texte chiffré
    decrypted_text = decrypt_aes(encrypted_text, key, iv)
    return decrypted_text

#from Crypto.Hash import SHA256

def hashStringIfPasswd(str):
    if len(str) == 43:
        return str
    if len(str) == 44 and str[-1] == "=":
        return str
    print("warning: the key you entered is too short, it has been hashed with SHA-256 for having a length of 43 characters. ")
    hash = SHA256.new(str.encode()).hexdigest()
    hashSlice = hash[:43]
    return hashSlice



#interact with the user

print("MENU AES ENCRYPTION")
print("1 Encrypt")
print("2 Decrypt")
print("3 New Key generation")
print("4 Exit\n")

mode = input()
if mode == "1":
    print("Message :")
    text_user_input = input()
    print("Key :")
    key_user_input = input()

    final_cipher_text = encrypt_aes_base64(text_user_input, key_user_input)
    print(f"IV + Texte chiffré : \n{final_cipher_text}")

elif mode == "2":
    print("Message :")
    text_user_input = input()
    print("Key :")
    key_user_input = input()
    
    decrypted_text = decrypt_aes_base64(text_user_input, key_user_input)
    print(f"Texte déchiffré : \n{decrypted_text}")
    
elif mode == "3":
    # Générer une clé AES de 256 bits
    key_base64 = generate_key()
    print(f"Clé en base64: {key_base64}")

elif mode == "4":
    print("Exiting...")


else:
    print("Please enter a valid mode")
