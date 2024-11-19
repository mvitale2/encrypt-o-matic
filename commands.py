# https://www.comparitech.com/blog/information-security/what-is-fernet/

from cryptography.fernet import Fernet
from re import sub

class Crypto():
    def __init__(self):
        self.fkey = Fernet.generate_key()
        self.f = Fernet(self.fkey)
    
    def new_fernet_key(self):
        self.fkey = Fernet.generate_key()
        return self.fkey
    
    def encrypt(self, text):
        text = text.encode()
        return self.f.encrypt(text)
    
    def decrypt(self, token):
        token = token.encode()
        return self.f.decrypt(token)
    
    def encrypt_file(self, text, name):
        with open(text, "w+") as file:
            plaintext = file.read()
            ciphertext = self.encrypt(plaintext)
            with open(f".\\output\\{name}.txt", "w") as modified_file:
                modified_file.write(ciphertext.decode())
    
    def decrypt_file(self, ciphertext, name):
        with open(ciphertext, "r") as file:
            target = file.readline()
            print(target)
            plaintext = self.decrypt(target)
            print(plaintext)
            with open(f".\\output\\{name}.txt", "w") as new_file:
                new_file.write(plaintext.decode())