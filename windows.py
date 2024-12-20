import customtkinter as ctk
from commands import FernetEncryption, VigenereCipher, DoubleIndexSubstitutionCipher
from CTkMessagebox import CTkMessagebox as Messagebox

class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("400x150")
        self.title("Encrypt-o-matic")
        self.fernet_window = None
        self.vigenere_window = None
        self.doubling_window = None
        # dev mode for automatically opening windows
        self.auto_start = False

        if self.auto_start:
            self.open_fernet()
    
        # elements
        self.fernet_btn = ctk.CTkButton(self, text="Use Fernet Encryption", command=self.open_fernet)
        self.fernet_btn.pack(pady=5)
        self.vigenere_btn = ctk.CTkButton(self, text="Use Vigenere Cipher", command=self.open_vigenere)
        self.vigenere_btn.pack(pady=5)
        self.double_index_btn = ctk.CTkButton(self, text="Use Double Index Caesar Cipher", command=self.open_doubling)
        self.double_index_btn.pack(pady=5)
    
    def open_fernet(self):
        if self.fernet_window is None or not self.fernet_window.winfo_exists():
            self.fernet_window = FernetWindow()  # create window if it's None or destroyed
            self.fernet_window.focus()
        else:
            self.fernet_window.focus()  # if window exists focus it
    
    def open_vigenere(self):
        if self.vigenere_window is None or not self.vigenere_window.winfo_exists():
            self.vigenere_window = VigenereWindow()  # create window if it's None or destroyed
            self.vigenere_window.focus()
        else:
            self.vigenere_window.focus()  # if window exists focus it
    
    def open_doubling(self):
        if self.doubling_window is None or not self.doubling_window.winfo_exists():
            self.doubling_window = DoublingWindow()  # create window if it's None or destroyed
            self.doubling_window.focus()
        else:
            self.doubling_window.focus()  # if window exists focus it

class FernetWindow(ctk.CTkToplevel):
    def __init__(self):
        super().__init__()
        self.geometry("305x400")
        self.title("Encrypt-o-matic -- Fernet")
        self.crypto = FernetEncryption()
        self.hide_key = ctk.StringVar(value="on")
        self.switch_value = ctk.StringVar(value="on")
        self.ciphertext = None
        self.plaintext = None
        self.key = self.crypto.key

        # elements
        # add encrypt/decrypt toggle
        self.key_toggle = ctk.CTkCheckBox(self, text="Hide Key?", command=self.hide_event, variable=self.hide_key, onvalue="on", offvalue="off")
        self.key_toggle.grid(row=0, column=0, columnspan=2)

        self.key_label = ctk.CTkTextbox(self, state="disabled", width=250, height=50)
        self.key_label.grid(row=1, column=0, columnspan=2)

        self.generate_key_btn = ctk.CTkButton(self, text="Generate new key", command=self.key_callback)
        self.generate_key_btn.grid(row=2, column=0, pady=(10,0))

        self.custom_key_btn = ctk.CTkButton(self, text="Enter a key", command=self.custom_key_callback)
        self.custom_key_btn.grid(row=2, column=1, pady=(10,0))

        self.input_label = ctk.CTkLabel(self, text="Plaintext")
        self.input_label.grid(row=4, column=0, columnspan=2)

        self.text_entry = ctk.CTkTextbox(self, width=250, height=80)
        self.text_entry.grid(row=5, column=0, columnspan=2)

        self.submit_btn = ctk.CTkButton(self, text="Encrypt", command=self.encrypt_callback)
        self.submit_btn.grid(row=6, column=0, pady=10)

        self.switch = ctk.CTkSwitch(self, text="Encrypt", variable=self.switch_value, onvalue="on", offvalue="off", command=self.switch_callback)
        self.switch.grid(row=6, column=1, pady=10)

        self.result_title = ctk.CTkLabel(self, text="Result")
        self.result_title.grid(row=7, column=0, columnspan=2)

        self.result_label = ctk.CTkTextbox(self, width=250, height=80)
        self.result_label.grid(row=8, column=0, columnspan=2)

        # Necessary for columnspan
        self.grid_columnconfigure(1, weight=1)

    def switch_callback(self):
        value = self.switch_value.get()
        if value == "on":
            self.switch.configure(text="Encrypt")
            self.submit_btn.configure(text="Encrypt", command=self.encrypt_callback)
            self.input_label.configure(text="Plaintext")
        elif value == "off":
            self.switch.configure(text="Decrypt")
            self.submit_btn.configure(text="Decrypt", command=self.decrypt_callback)
            self.input_label.configure(text="Ciphertext")
    
    def encrypt_callback(self):
        entry = self.text_entry.get(index1="0.0", index2="end").strip()
        self.ciphertext = None
        self.plaintext = None
        if entry != "":
            self.ciphertext = self.crypto.encrypt(entry)
            self.result_label.delete(index1="0.0", index2="end")
            self.result_label.insert(index="0.0", text=self.ciphertext.decode())
        else:
            self.result_label.delete(index1="0.0", index2="end")
            self.result_label.insert(index="0.0",text="Invalid entry")

    def decrypt_callback(self):
        entry = self.text_entry.get(index1="0.0", index2="end").strip()
        if entry != None:
            self.plaintext = self.crypto.decrypt(entry)
            self.result_label.delete(index1="0.0", index2="end")
            self.result_label.insert(index="0.0", text=self.plaintext.decode())
        else:
            self.result_label.delete(index1="0.0", index2="end")
            self.result_label.insert(index="0.0",text="Invalid entry")
    
    def hide_event(self):
        self.key_label.configure(state="normal")
        if self.key_toggle.get() == "on":
            self.key_label.delete(index1="0.0", index2="end")
        elif self.key_toggle.get() == "off":
            self.key_label.insert(index="0.0", text=self.key)
        self.key_label.configure(state="disabled")
    
    def key_callback(self):
        self.crypto.key = self.crypto.new_key()
        self.key = self.crypto.key
        if self.hide_key.get() == "off":
            # Only shows the new key if the label is not hidden
            self.key_label.configure(state="normal")
            self.key_label.delete(index1="0.0", index2="end")
            self.key_label.insert(index="0.0", text=self.key)
            self.key_label.configure(state="disabled")
    
    def custom_key_callback(self):
        dialog = ctk.CTkInputDialog(text="Enter a Fernet key", title="Custom Key")
        input = dialog.get_input()
        if input != None:
            self.crypto.key = input.encode()
            self.key = self.crypto.key
            if self.hide_key.get() == "off":
                self.key_label.configure(state="normal")
                self.key_label.delete(index1="0.0", index2="end")
                self.key_label.insert(index="0.0", text=self.key.decode())
                self.key_label.configure(state="disabled")

class VigenereWindow(ctk.CTkToplevel):
    def __init__(self):
        super().__init__()
        self.geometry("305x400")
        self.title("Encrypt-o-Matic -- Vigenere")
        self.key = None
        self.switch_value = ctk.StringVar(value="on")
        self.show_key = ctk.StringVar(value="off")

        # elements
        self.key_label = ctk.CTkTextbox(self, width=100, height=30, state="disabled")
        self.key_label.grid(row=0, column=0, columnspan=2)

        self.new_key_btn = ctk.CTkButton(self, text="New Key", command=self.new_key_callback)
        self.new_key_btn.grid(row=1, column=0)

        self.show_key_toggle = ctk.CTkCheckBox(self, text="Show Key?", variable=self.show_key, command=self.show_key_callback, onvalue="on", offvalue="off")
        self.show_key_toggle.grid(row=1, column=1)

        self.encrypt_label = ctk.CTkLabel(self, text="Plaintext")
        self.encrypt_label.grid(row=2, column=0, columnspan=2)

        self.text_entry = ctk.CTkTextbox(self, width=200, height=100, wrap="word")
        self.text_entry.grid(row=3, column=0, columnspan=2)

        self.submit_btn = ctk.CTkButton(self, text="Encrypt", command=self.encrypt_callback)
        self.submit_btn.grid(row=4, column=0, pady=10)

        self.swap_btn = ctk.CTkButton(self, text="Swap", command=self.swap_callback)
        self.swap_btn.grid(row=4, column=1, pady=10)

        self.result_label = ctk.CTkLabel(self, text="Ciphertext")
        self.result_label.grid(row=5, column=0, columnspan=2)

        self.result_box = ctk.CTkTextbox(self, width=200, height=100)
        self.result_box.grid(row=6, column=0, columnspan=2)

        self.switch = ctk.CTkSwitch(self, text="Encrypt", command=self.switch_event, variable=self.switch_value, onvalue="on", offvalue="off")
        self.switch.grid(row=7, column=0, columnspan=2)

        # Necessary for columnspan
        self.grid_columnconfigure(1, weight=1)
    
    def no_key_found(self):
        Messagebox(message="Please enter a key first.", title="No Key Found", icon="cancel")

    def swap_callback(self):
        plaintext = self.text_entry.get(index1="0.0", index2="end").strip()
        ciphertext = self.result_box.get(index1="0.0", index2="end").strip()
        self.text_entry.delete(index1="0.0", index2="end")
        self.result_box.delete(index1="0.0", index2="end")
        self.text_entry.insert(index="0.0", text=ciphertext)
        self.result_box.insert(index="0.0", text=plaintext)

    def switch_event(self):
        value = self.switch_value.get()
        if value == "on":
            self.switch.configure(text="Encrypt")
            self.submit_btn.configure(text="Encrypt", command=self.encrypt_callback)
        elif value == "off":
            self.switch.configure(text="Decrypt")
            self.submit_btn.configure(text="Decrypt", command=self.decrypt_callback)
    
    def new_key_callback(self):
        dialog = ctk.CTkInputDialog(text="Enter a new key:")
        input = dialog.get_input()
        if input != None:
            self.key = input
            if self.show_key.get() == "on":
                self.key_label.configure(state="normal")
                self.key_label.delete(index1="0.0", index2="end")
                self.key_label.insert(index="0.0", text=self.key)
                self.key_label.configure(state="disabled")
        else:
            Messagebox(message="No key was given. Using previous key.", title="Cancelled")
    
    def show_key_callback(self):
        if self.key == None:
            self.no_key_found()
        elif self.show_key.get() == "on":
            self.key_label.configure(state="normal")
            self.key_label.delete(index1="0.0", index2="end")
            self.key_label.insert(index="0.0", text=self.key)
            self.key_label.configure(state="disabled")
        elif self.show_key.get() == "off":
            self.key_label.configure(state="normal")
            self.key_label.delete(index1="0.0", index2="end")
            self.key_label.configure(state="disabled")
    
    def encrypt_callback(self):
        if self.key != None:
            crypto = VigenereCipher(self.key)
            plaintext = self.text_entry.get(index1="0.0", index2="end").strip()
            if plaintext != "":
                self.result_box.delete(index1="0.0", index2="end")
                ciphertext = crypto.vigenere_cipher(plaintext, "encrypt")
                self.result_box.insert(index="0.0", text=ciphertext)
            else:
                self.result_box.delete(index1="0.0", index2="end")
                self.result_box.insert(index="0.0", text="Invalid Entry")
        else:
            self.no_key_found()
            self.result_box.delete(index1="0.0", index2="end")
    
    def decrypt_callback(self):
        if self.key != None:
            crypto = VigenereCipher(self.key)
            ciphertext = self.text_entry.get(index1="0.0", index2="end").strip()
            if ciphertext != "":
                self.result_box.delete(index1="0.0", index2="end")
                plaintext = crypto.vigenere_cipher(ciphertext, "decrypt")
                self.result_box.insert(index="0.0", text=plaintext)
            else:
                self.result_box.delete(index1="0.0", index2="end")
                self.result_box.insert(index="0.0", text="Invalid Entry")
        else:
            self.no_key_found()
            self.result_box.delete(index1="0.0", index2="end")

class DoublingWindow(ctk.CTkToplevel):
    def __init__(self):
        super().__init__()
        self.geometry("305x400")
        self.title("Encrypt-o-matic -- Double Index Substitution")
        self.crypto = DoubleIndexSubstitutionCipher()
        self.switch_value = ctk.StringVar(value="on")
    
        # elements
        self.encrypt_label = ctk.CTkLabel(self, text="Plaintext")
        self.encrypt_label.grid(row=0, column=0, columnspan=2)

        self.text_entry = ctk.CTkTextbox(self, width=200, height=100, wrap="word")
        self.text_entry.grid(row=1, column=0, columnspan=2)

        self.submit_btn = ctk.CTkButton(self, text="Encrypt", command=self.encrypt_callback)
        self.submit_btn.grid(row=2, column=0, pady=10)

        self.swap_btn = ctk.CTkButton(self, text="Swap", command=self.swap_callback)
        self.swap_btn.grid(row=2, column=1, pady=10)

        self.result_label = ctk.CTkLabel(self, text="Ciphertext")
        self.result_label.grid(row=3, column=0, columnspan=2)

        self.result_box = ctk.CTkTextbox(self, width=200, height=100, wrap="word")
        self.result_box.grid(row=4, column=0, columnspan=2)

        self.switch = ctk.CTkSwitch(self, text="Encrypt", command=self.switch_event, variable=self.switch_value, onvalue="on", offvalue="off")
        self.switch.grid(row=5, column=0, columnspan=2)

        self.grid_columnconfigure(1, weight=1)

    def encrypt_callback(self):
        plaintext = self.text_entry.get(index1="0.0", index2="end").strip()
        if plaintext != "":
            self.result_box.delete(index1="0.0", index2="end")
            ciphertext = self.crypto.double_index_sub_cipher(plaintext)
            self.result_box.insert(index="0.0", text=ciphertext)
        else:
            self.result_box.delete(index1="0.0", index2="end")
            self.result_box.insert(index="0.0", text="Invalid Entry")
    
    def decrypt_callback(self):
        ciphertext = self.result_box.get(index1="0.0", index2="end").strip()
        if ciphertext != "":
            self.text_entry.delete(index1="0.0", index2="end")
            plaintext = self.crypto.double_index_sub_cipher(ciphertext)
            self.text_entry.insert(index="0.0", text=plaintext)
        else:
            self.text_entry.delete(index1="0.0", index2="end")
            self.text_entry.insert(index="0.0", text="Invalid Entry")
    
    def switch_event(self):
        value = self.switch_value.get()
        if value == "on":
            self.switch.configure(text="Encrypt")
            self.submit_btn.configure(text="Encrypt", command=self.encrypt_callback)
        elif value == "off":
            self.switch.configure(text="Decrypt")
            self.submit_btn.configure(text="Decrypt", command=self.decrypt_callback)
    
    def swap_callback(self):
        plaintext = self.text_entry.get(index1="0.0", index2="end").strip()
        ciphertext = self.result_box.get(index1="0.0", index2="end").strip()
        self.text_entry.delete(index1="0.0", index2="end")
        self.result_box.delete(index1="0.0", index2="end")
        self.text_entry.insert(index="0.0", text=ciphertext)
        self.result_box.insert(index="0.0", text=plaintext)

