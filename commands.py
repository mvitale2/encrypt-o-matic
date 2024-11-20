from cryptography.fernet import Fernet

class FernetEncryption:
    # https://www.comparitech.com/blog/information-security/what-is-fernet/

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
            print(plaintext.decode())
            with open(f".\\output\\{name}.txt", "w") as new_file:
                new_file.write(plaintext.decode())

class DoubleIndexCaesarCipher:
    def double_index_caesar_cipher(self, text):
        def shift_char(c):
            if c.isalpha():  # Check if character is a letter
                is_upper = c.isupper()
                alphabet_start = ord('A') if is_upper else ord('a')
                
                # Get alphabetical index (1-based)
                alphabetical_index = ord(c) - alphabet_start + 1
                
                # Calculate shift (double the index)
                shift = alphabetical_index * 2
                
                # Apply the shift, wrap around with modulo 26
                new_char = chr(alphabet_start + (alphabetical_index - 1 + shift) % 26)
                return new_char
            else:
                return c  # Non-alphabetic characters remain unchanged
        # Apply the shift_char function to each character in the input text
        return ''.join(shift_char(c) for c in text)

    # def decrypt_double_index(self, ciphertext):
    #     def un_shift_char(c):
    #         if c.isalpha():
    #             is_upper = c.isupper()
    #             alphabet_start = ord("A") if is_upper else ord('a')
    #             encrypted_index = ord(c) - alphabet_start
    #             for original_index in range(26):
    #                 if (original_index * 2) % 26 == encrypted_index:
    #                     return chr(alphabet_start + original_index)
    #             return c
    #         else:
    #             return c # non-alphanumeric characters are ignored
    #     return ''.join(un_shift_char(c) for c in ciphertext)