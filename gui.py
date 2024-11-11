import customtkinter as ctk
from commands import Crypto

class Gui(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("400x200")
        self.crypto = Crypto()
        
        # elements
        self.encrypt_entry = ctk.CTkEntry(self, placeholder_text="message")
        self.encrypt_entry.pack()
        self.encrypt_btn = ctk.CTkButton(self, text="Encrypt", command=self.encrypt_callback)
        self.encrypt_btn.pack()
        self.result_label = ctk.CTkLabel(self, text=None)
        self.result_label.pack()
    
    def encrypt_callback(self):
        entry = self.encrypt_entry.get()
        print(entry)
        if entry != None or '':
            ciphertext = self.crypto.encrypt(entry)
            self.result_label.configure(text=ciphertext)
        else:
            self.result_label.configure(text="Invalid entry")
