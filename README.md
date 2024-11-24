# Encrypt-o-Matic
This is a small GUI program written using [customtkinter](https://customtkinter.tomschimansky.com/).

Its main purpose is to encrypt text and only text. There is no option to import files or text from files. 

You can choose from three different algorithms upon opening the program:
- Fernet Encryption
- Vigenere Cipher
- Double Index Substitution Cipher

Selecting an algorithm opens a new window where the user can enter the text they wish to encrypt. 

Fernet and Vigenere use private keys in order to encrypt text. The GUI makes it simple to input keys so that two (or more) parties can securely send messages to each other via messaging applications. It would be best to share the key outside of said applications (voice chat, in-person communication, etc.) in order to maximize security. 

The Double Index cipher can be decrypted simply by running an encrypted message through the algorithm twice. 

Created at Oakland University for CSI 3480 -- *Security and Privacy in Computing* taught by Professor Solmaz Salehian. 