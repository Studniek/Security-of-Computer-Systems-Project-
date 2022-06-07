import tkinter as tk
import hashlib
from constants import *


class EnterLocalKeyWindow:
    def __init__(self, parent):
        self.parent = parent  # Parent is the MainWindow
        self.root = tk.Toplevel(parent.root)
        self.root.title("Generate Local Key")
        self.root.geometry("300x150")

        # Password
        self.passwordLabel = tk.Label(self.root, text="Enter password to cipher your private key:")
        self.passwordEntry = tk.Entry(self.root, show="*")
        self.passwordEntry.insert(tk.END, '1234')

        # Password
        self.repeatPasswordLabel = tk.Label(self.root, text="Repeat password")
        self.repeatPasswordEntry = tk.Entry(self.root, show="*")
        self.repeatPasswordEntry.insert(tk.END, '1234')

        self.submitButton = tk.Button(self.root, text="Submit", padx=10, pady=5,
                                      fg="white", bg=WINDOWS_BG_COLOR,
                                      command=self.checkPassword)

        self.passwordLabel.pack()
        self.passwordEntry.pack()
        self.repeatPasswordLabel.pack()
        self.repeatPasswordEntry.pack()
        self.submitButton.pack()

    def checkPassword(self):
        password = self.passwordEntry.get()
        repeatPassword = self.repeatPasswordEntry.get()

        print("Password: " + password)
        print("Repeated password: " + repeatPassword)

        if password != repeatPassword:
            tk.messagebox.showerror(title="Wrong password", message="Password doesn't match!")

        else:
            self.root.destroy()
            hashed_password = hashlib.sha256(password.encode('utf-8')).digest()
            print("Hashed password:" + str(hashed_password)+"\n\n\n")
            self.parent.keyManager.localKeyHash = hashed_password
