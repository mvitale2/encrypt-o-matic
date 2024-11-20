import customtkinter as ctk
from commands import FernetEncryption, DoubleIndexCaesarCipher
from os import getcwd
from os.path import join

class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("400x150")
        self.title("Encrypt-o-matic")
        self.fernet_window = None
        self.doubling_window = None
        # dev mode for automatically opening windows
        self.auto_start = True

        if self.auto_start:
            self.open_doubling()
    
        # elements
        self.fernet_btn = ctk.CTkButton(self, text="Use Fernet Encryption", command=self.open_fernet)
        self.fernet_btn.pack(pady=5)
        self.vigenere_btn = ctk.CTkButton(self, text="Use Vigenere Cipher")
        self.vigenere_btn.pack(pady=5)
        self.double_index_btn = ctk.CTkButton(self, text="Use Double Index Caesar Cipher", command=self.open_doubling)
        self.double_index_btn.pack(pady=5)
    
    def open_fernet(self):
        if self.fernet_window is None or not self.fernet_window.winfo_exists():
            self.fernet_window = FernetWindow()  # create window if it's None or destroyed
            self.fernet_window.focus()
        else:
            self.fernet_window.focus()  # if window exists focus it
    
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
        self.title("Encrypt-o-matic")
        self.crypto = FernetEncryption()
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
        self.custom_key_btn.grid(row=3, column=0, columnspan=2, pady=(0,10))

        self.encrypt_file_btn = ctk.CTkButton(self, text="Encrypt file", command=self.e_file_callback)
        self.encrypt_file_btn.grid(row=4, column=0)

        self.decrypt_file_btn = ctk.CTkButton(self, text="Decrypt file", command=self.d_file_callback)
        self.decrypt_file_btn.grid(row=4, column=1)

        self.encrypt_entry = ctk.CTkEntry(self, placeholder_text="message")
        self.encrypt_entry.grid(row=5, column=0, columnspan=2)

        self.encrypt_btn = ctk.CTkButton(self, text="Encrypt", command=self.encrypt_callback)
        self.encrypt_btn.grid(row=6, column=0, columnspan=2, pady=10)

        self.decrypt_entry = ctk.CTkEntry(self, placeholder_text="token")
        self.decrypt_entry.grid(row=7, column=0, columnspan=2)

        self.decrypt_button = ctk.CTkButton(self, text="Decrypt", command=self.decrypt_callback)
        self.decrypt_button.grid(row=8, column=0, columnspan=2, pady=10)

        self.result_label = ctk.CTkLabel(self, text=None, width=20, height=20)
        self.result_label.grid(row=9, column=0, columnspan=2)
    
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
    
    def e_file_callback(self):
        file = ctk.filedialog.askopenfilename()
        # Check for cancellation
        if file != "":
            dialog = ctk.CTkInputDialog(text=f"Enter a name for the encrypted file.\nMake sure you've used the correct key!\nEncrypted files are saved to {join(getcwd(), "output\\")}", title="New File Name")
            name = dialog.get_input()
            # Check for cancellation
            if name != None:
                self.crypto.encrypt_file(file, name)

    def d_file_callback(self):
        file = ctk.filedialog.askopenfilename()
        # Check for cancellation
        if file != "":
            dialog = ctk.CTkInputDialog(text=f"Enter a name for the decrypted file.\nMake sure you've used the correct key!\nEncrypted files are saved to {join(getcwd(), "output\\")}", title="New File Name")
            name = dialog.get_input()
            # Check for cancellation
            if name != None:
                self.crypto.decrypt_file(file, name)
    
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
            self.crypto.key = input
            self.key = input
            self.key_label.configure(text=self.key)

class DoublingWindow(ctk.CTkToplevel):
    def __init__(self):
        super().__init__()
        self.geometry("305x400")
        self.title("Encrypt-o-matic")
        self.crypto = DoubleIndexCaesarCipher()
        self.switch_value = ctk.StringVar(value="on")
    
        # elements
        self.encrypt_label = ctk.CTkLabel(self, text="Plaintext")
        self.encrypt_label.grid(row=0, column=0, columnspan=2)

        self.text_entry = ctk.CTkTextbox(self, width=200, height=100)
        self.text_entry.grid(row=1, column=0, columnspan=2)

        self.submit_btn = ctk.CTkButton(self, text="Encrypt", command=self.encrypt_callback)
        self.submit_btn.grid(row=2, column=0, pady=10)

        self.swap_btn = ctk.CTkButton(self, text="Swap", command=self.swap_callback)
        self.swap_btn.grid(row=2, column=1, pady=10)

        self.result_label = ctk.CTkLabel(self, text="Ciphertext")
        self.result_label.grid(row=3, column=0, columnspan=2)

        self.result_box = ctk.CTkTextbox(self, width=200, height=100)
        self.result_box.grid(row=4, column=0, columnspan=2)

        self.switch = ctk.CTkSwitch(self, text="Encrypt", command=self.switch_event, variable=self.switch_value, onvalue="on", offvalue="off")
        self.switch.grid(row=5, column=0, columnspan=2)

        self.grid_columnconfigure(1, weight=1)

    def encrypt_callback(self):
        plaintext = self.text_entry.get(index1="0.0", index2="end").strip()
        if plaintext != "":
            self.result_box.delete(index1="0.0", index2="end")
            ciphertext = self.crypto.double_index_caesar_cipher(plaintext)
            self.result_box.insert(index="0.0", text=ciphertext)
        else:
            self.result_box.delete(index1="0.0", index2="end")
            self.result_box.insert(index="0.0", text="Invalid Entry")
    
    def decrypt_callback(self):
        ciphertext = self.result_box.get(index1="0.0", index2="end").strip()
        if ciphertext != "":
            self.text_entry.delete(index1="0.0", index2="end")
            plaintext = self.crypto.double_index_caesar_cipher(ciphertext)
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

