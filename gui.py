import customtkinter as ctk
from commands import Crypto

class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("400x100")
        self.title("Encrypt-o-matic")
        self.fernet_window = None
        # dev mode for automatically opening windows
        self.auto_start = True

        if self.auto_start:
            self.open_fernet()
    
        # elements
        self.fernet_btn = ctk.CTkButton(self, text="Use Fernet Encryption", command=self.open_fernet)
        self.fernet_btn.pack()
        self.vigenere_btn = ctk.CTkButton(self, text="Use Vigenere Cipher")
        self.vigenere_btn.pack()
    
    def open_fernet(self):
        if self.fernet_window is None or not self.fernet_window.winfo_exists():
            self.fernet_window = FernetWindow()  # create window if it's None or destroyed
            self.fernet_window.focus()
        else:
            self.fernet_window.focus()  # if window exists focus it


class FernetWindow(ctk.CTkToplevel):
    def __init__(self):
        super().__init__()
        self.geometry("305x400")
        self.title("Encrypt-o-matic")
        self.crypto = Crypto()
        self.copy = ctk.BooleanVar()
        self.hide_key = ctk.BooleanVar()
        self.ciphertext = None
        self.plaintext = None
        self.key = self.crypto.fkey

        # elements
        self.copy_toggle = ctk.CTkCheckBox(self, text="Copy results?", variable=self.copy, onvalue=False, offvalue=True)
        self.copy_toggle.grid(row=0, column=0)

        self.key_toggle = ctk.CTkCheckBox(self, text="Hide Key?", command=self.hide_event, variable=self.hide_key, onvalue=False, offvalue=True)
        self.key_toggle.grid(row=0, column=1)

        self.key_label = ctk.CTkLabel(self, text="")
        self.key_label.grid(row=1, column=0, columnspan=2)

        self.generate_key_btn = ctk.CTkButton(self, text="Generate new key", command=self.key_callback)
        self.generate_key_btn.grid(row=2, column=0, padx=10, pady=10)

        self.copy_key_button = ctk.CTkButton(self, text="Copy key", command=self.key_copy_callback)
        self.copy_key_button.grid(row=2, column=1)

        self.custom_key_btn = ctk.CTkButton(self, text="Enter a key", command=self.custom_key_callback)
        self.custom_key_btn.grid(row=2, column=3)

        self.encrypt_entry = ctk.CTkEntry(self, placeholder_text="message")
        self.encrypt_entry.grid(row=3, column=0, columnspan=2)

        self.encrypt_btn = ctk.CTkButton(self, text="Encrypt", command=self.encrypt_callback)
        self.encrypt_btn.grid(row=4, column=0, columnspan=2, pady=10)

        self.decrypt_entry = ctk.CTkEntry(self, placeholder_text="token")
        self.decrypt_entry.grid(row=5, column=0, columnspan=2)

        self.decrypt_button = ctk.CTkButton(self, text="Decrypt", command=self.decrypt_callback)
        self.decrypt_button.grid(row=6, column=0, columnspan=2, pady=10)

        self.result_label = ctk.CTkLabel(self, text=None, width=20, height=20)
        self.result_label.grid(row=7, column=0, columnspan=2)
    
    def hide_event(self):
        if self.key_toggle.get() == False:
            self.key_label.configure(text="")
        else:
            self.key_label.configure(text=self.key)
    
    # add method that truncates output and shows a button to export output to .txt file
    # alternatively make the gui element bigger and capable of wrapping the output
    def encrypt_callback(self):
        entry = self.encrypt_entry.get()
        self.ciphertext = None
        self.plaintext = None
        if entry != "":
            self.ciphertext = self.crypto.encrypt(entry)
            self.result_label.configure(text=self.ciphertext.decode())
            if self.copy == True:
                self.clipboard_clear()
                self.clipboard_append(f"Result: {self.ciphertext.decode()}")
        else:
            self.result_label.configure(text="Invalid entry")
    
    def decrypt_callback(self):
        entry = self.decrypt_entry.get()
        if entry != None:
            try:
                self.plaintext = self.crypto.decrypt(entry)
                self.result_label.configure(text=f"Result: {self.plaintext.decode()}")
                if self.copy == True:
                    self.clipboard_clear()
                    self.clipboard_append(self.plaintext.decode())
            except:
                self.result_label.configure(text="Invalid entry.")
        else:
            self.result_label.configure(text="Invalid entry")
    
    def key_callback(self):
        self.key = self.crypto.new_fernet_key()
        self.key_label.configure(text=self.key)
    
    def key_copy_callback(self):
        self.clipboard_clear()
        self.clipboard_append(self.key)
    
    def custom_key_callback(self):
        dialog = ctk.CTkInputDialog(text="Enter a Fernet key", title="Custom Key")
        input = dialog.get_input()
        if input != None:
            self.key = input
            self.key_label.configure(text=self.key)

