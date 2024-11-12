import customtkinter as ctk
from commands import Crypto

class Gui(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("400x200")
        self.title("Encrypt-o-matic")
        self.crypto = Crypto()
        self.copy = True
        self.ciphertext = None
        self.plaintext = None
        
        # elements
        self.encrypt_entry = ctk.CTkEntry(self, placeholder_text="message")
        self.encrypt_entry.pack()
        self.encrypt_entry.insert(0, "")
        self.encrypt_btn = ctk.CTkButton(self, text="Encrypt", command=self.encrypt_callback)
        self.encrypt_btn.pack()
        self.decrypt_entry = ctk.CTkEntry(self, placeholder_text="token")
        self.decrypt_entry.insert(0, "")
        self.decrypt_entry.pack()
        self.decrypt_button = ctk.CTkButton(self, text="Decrypt", command=self.decrypt_callback)
        self.decrypt_button.pack()
        self.result_label = ctk.CTkLabel(self, text=None, width=20, height=20)
        self.result_label.pack()
    
    def encrypt_callback(self):
        entry = self.encrypt_entry.get()
        self.ciphertext = None
        self.plaintext = None
        print(f"Encrypting {entry}")
        if entry != "":
            self.ciphertext = self.crypto.encrypt(entry)
            self.result_label.configure(text=self.ciphertext.decode())
            if self.copy == True:
                self.clipboard_clear()
                self.clipboard_append(self.ciphertext.decode())
        else:
            self.result_label.configure(text="Invalid entry")
    
    def decrypt_callback(self):
        entry = self.decrypt_entry.get()
        print(f"Decrypting ${entry}")
        if entry != None:
            try:
                self.plaintext = self.crypto.decrypt(entry)
                self.result_label.configure(text=self.plaintext.decode())
                if self.copy == True:
                    self.clipboard_clear()
                    self.clipboard_append(self.plaintext.decode())
            except:
                self.result_label.configure(text="Invalid entry.")
        else:
            self.result_label.configure(text="Invalid entry")
