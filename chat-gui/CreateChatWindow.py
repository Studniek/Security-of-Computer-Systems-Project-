import json
import tkinter as tk
from constants import *
import socket


class CreateChatWindow:
    def __init__(self, parent):
        self.parent = parent  # Parent is the MainWindow
        self.root = tk.Toplevel(parent.root)
        self.root.title("Create chat")
        self.root.geometry("600x300")

        # Cipher Mode
        self.cipherModeLabel = tk.Label(self.root, text="Cipher mode:")
        self.cipherOptions = ["ECB", "CBC"]
        self.cipherMode = tk.StringVar()
        self.cipherMode.set(self.cipherOptions[0])
        self.cipherModeOptionMenu = tk.OptionMenu(self.root, self.cipherMode, *self.cipherOptions)

        # Destination IP
        self.ipLabel = tk.Label(self.root, text="Enter destination IP:")
        self.ipEntry = tk.Entry(self.root)
        self.ipEntry.insert(tk.END, '127.0.0.1')

        # Destination port
        self.destPortLabel = tk.Label(self.root, text="Enter destination port:")
        self.destPortEntry = tk.Entry(self.root)
        self.destPortEntry.insert(tk.END, '50012')

        self.submitButton = tk.Button(self.root, text="Submit", padx=10, pady=5,
                                      fg="white", bg=WINDOWS_BG_COLOR,
                                      command=self.startChat)

        self.cipherModeLabel.grid(row=0, column=0)
        self.cipherModeOptionMenu.grid(row=0, column=1)
        self.ipLabel.grid(row=3, column=0)
        self.ipEntry.grid(row=3, column=1)
        self.destPortLabel.grid(row=4, column=0)
        self.destPortEntry.grid(row=4, column=1)
        self.submitButton.grid(row=5, column=0)

    def startChat(self):
        print("Cipher mode:\t" + self.cipherMode.get())
        print("IP Address:\t" + self.ipEntry.get())
        print("Destination port:\t" + self.destPortEntry.get())

        self.parent.networkManager.destIP = self.ipEntry.get()
        self.parent.networkManager.destPort = int(self.destPortEntry.get())

        publicRSAKey = self.parent.keyManager.ownPublicKey.save_pkcs1().decode('utf-8')
        msg = 'Polaczenie zostalo utworzone'
        self.parent.showMessage(msg)

        json_data = json.dumps(
            {'messageType': MessageType.handshake.value, 'destinationPort': self.parent.networkManager.destPort,
             'message': msg, 'publicRSAKey': publicRSAKey})

        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        senderSocket.connect(('127.0.0.1', self.parent.networkManager.destPort))
        senderSocket.sendall(json_data.encode())
        senderSocket.close()

        self.root.destroy()
