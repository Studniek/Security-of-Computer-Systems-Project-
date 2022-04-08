import tkinter as tk
import constants as consts


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

        # IP
        self.ipLabel = tk.Label(self.root, text="Enter IP:")
        self.ipEntry = tk.Entry(self.root)
        self.ipEntry.insert(tk.END, '192.168.0.123')

        self.submitButton = tk.Button(self.root, text="Submit", padx=10, pady=5,
                                      fg="white", bg=consts.WINDOWS_BG_COLOR,
                                      command=self.startChat)

        self.cipherModeLabel.grid(row=0, column=0)
        self.cipherModeOptionMenu.grid(row=0, column=1)
        self.ipLabel.grid(row=1, column=0)
        self.ipEntry.grid(row=1, column=1)
        self.submitButton.grid(row=5, column=0)

    def startChat(self):
        print("Cipher mode:\t" + self.cipherMode.get())
        print("IP Address:\t" + self.ipEntry.get())

        self.root.destroy()
