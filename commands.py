# https://www.comparitech.com/blog/information-security/what-is-fernet/

from cryptography.fernet import Fernet

class Crypto():
    def __init__(self):
        self.key = Fernet.generate_key()
        self.f = Fernet(self.key)
    
    def encrypt(self, text):
        return self.f.encrypt(text)
    
    def decrypt(self, token):
        return self.f.decrypt(token)