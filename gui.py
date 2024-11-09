import customtkinter as ctk
from os import getcwd

class Gui(ctk.CTk):
    def __init__(self):
        self.cwd = getcwd()