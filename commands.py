# https://www.comparitech.com/blog/information-security/what-is-fernet/

from cryptography.fernet import Fernet

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