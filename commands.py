from cryptography.fernet import Fernet

class FernetEncryption:
    # https://www.comparitech.com/blog/information-security/what-is-fernet/
    # A simple algorithm that works out of the box in python, no self-written logic necessary

    def __init__(self):
        self.key = self.new_key()
        self.f = Fernet(self.key)
    
    def new_key(self):
        key = Fernet.generate_key()
        return key
    
    def encrypt(self, text):
        text = text.encode()
        return self.f.encrypt(text)
    
    def decrypt(self, token):
        token = token.encode()
        return self.f.decrypt(token)
    
    # Commented because it wasn't working properly
    # def encrypt_file(self, text, name):
    #     with open(text, "w+") as file:
    #         plaintext = file.read()
    #         ciphertext = self.encrypt(plaintext)
    #         with open(f".\\output\\{name}.txt", "w") as modified_file:
    #             modified_file.write(ciphertext.decode())
    
    # def decrypt_file(self, ciphertext, name):
    #     with open(ciphertext, "r") as file:
    #         target = file.readline()
    #         print(target)
    #         plaintext = self.decrypt(target)
    #         print(plaintext.decode())
    #         with open(f".\\output\\{name}.txt", "w") as new_file:
    #             new_file.write(plaintext.decode())

class DoubleIndexSubstitutionCipher:
    def double_index_sub_cipher(self, text):
        """
        A substitution cipher that replaces each letter's alphabetical index with the index plus the index multiplied by 2. 
        For example, a becomes c because 1 x 2 = 2 + 1 = 3.  
        """
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

class VigenereCipher:
    def __init__(self, key):
        self.key = key
    
    def vigenere_cipher(self, text, mode):
        """
        Encrypts or decrypts text using the Vigenere cipher. The key attribute is used to encrypt or decrypt the text. 

        Args:
        text: The text to encrypt or decrypt.
        mode: 'encrypt' or 'decrypt'.

        Returns:
        The encrypted or decrypted text.
        """

        result = ''
        key_index = 0
        key = self.key.upper()

        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                if mode == 'decrypt':
                    shift = -shift

                shifted_char = chr(((ord(char.upper()) - ord('A') + shift) % 26) + ord('A'))

                if char.islower():
                    shifted_char = shifted_char.lower()

                result += shifted_char
                key_index += 1
            else:
                result += char

        return result