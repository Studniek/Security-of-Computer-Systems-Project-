import CreateChatWindow as ccw
from constants import *
import tkinter as tk
from tkinter import filedialog
import KeyManager as km
import NetworkManager as nm


class MainWindow:
    def __init__(self, listenerPort=5050, senderPort=5051, title="BSK: Secure p2p chat"):
        # # NETWORK
        self.networkManager = nm.NetworkManager(self, listenerPort, senderPort)

        # KEYS
        self.keyManager = km.KeyManager(self)

        # GUI
        self.root = tk.Tk()
        self.root.title(title)

        self.canvas = tk.Canvas(self.root, height=WINDOW_HEIGHT, width=WINDOW_WIDTH,
                                bg=WINDOWS_BG_COLOR)
        self.canvas.pack()

        self.frame = tk.Frame(self.root, bg="white")
        self.frame.place(relwidth=0.8, relheight=0.8, relx=0.1, rely=0.1)

        self.chatLabel = tk.Label(self.frame, text="Chat window")
        self.chatTextBox = tk.Text(self.frame, bg="light blue", width=80, height=20, state='disabled')
        self.createChatButton = tk.Button(self.root, text="Create Chat", padx=10, pady=5,
                                          fg="white", bg=WINDOWS_BG_COLOR,
                                          command=lambda: ccw.CreateChatWindow(self))
        self.clearChatButton = tk.Button(self.frame, text="Clear chat", padx=10, pady=5,
                                         fg="white", bg=WINDOWS_BG_COLOR, command=self.clearChat)

        self.enterMessageLabel = tk.Label(self.frame, text="Enter your message")
        self.enterMessageTextBox = tk.Text(self.frame, bg="light blue", width=50, height=2)
        self.sendMessageButton = tk.Button(self.frame, text="Send your message", padx=10, pady=5,
                                           fg="white", bg=WINDOWS_BG_COLOR, command=self.sendMessageButtonFunction)

        self.addFileButton = tk.Button(self.frame, text="Add File", padx=10, pady=5,
                                       fg="white", bg=WINDOWS_BG_COLOR, command=self.addFile)

        self.generateKeysButton = tk.Button(self.frame, text="Generate RSA Keys", padx=10, pady=5,
                                            fg="white", bg=WINDOWS_BG_COLOR,
                                            command=self.keyManager.generateRSAKeys)

        self.loadKeysButton = tk.Button(self.frame, text="Load RSA Keys", padx=10, pady=5,
                                        fg="white", bg=WINDOWS_BG_COLOR,
                                        command=self.keyManager.loadRSAKeys)

        self.createChatButton.pack()
        self.chatLabel.pack()
        self.chatTextBox.pack()
        self.enterMessageLabel.pack()
        self.enterMessageTextBox.pack()
        self.sendMessageButton.pack()
        self.clearChatButton.pack()
        self.addFileButton.pack()
        self.generateKeysButton.pack()
        self.loadKeysButton.pack()

        self.root.mainloop()

    def addFile(self):
        filenames = filedialog.askopenfilenames(initialdir="/", title="Select File")
        for filename in filenames:
            # LOADING FILES TO MEMORY AND SENDING THEM TO ANOTHER USER HERE...
            print(filename)

    def sendMessageButtonFunction(self):
        msg = self.enterMessageTextBox.get("1.0", tk.END)
        self.showMessage(msg)
        self.networkManager.sendMessage(msg)

    def showMessage(self, msg):
        self.chatTextBox.config(state=tk.NORMAL)
        self.chatTextBox.insert(tk.INSERT, msg)
        self.chatTextBox.config(state=tk.DISABLED)

    def clearChat(self):
        self.chatTextBox.config(state=tk.NORMAL)
        self.chatTextBox.delete('1.0', tk.END)
        self.chatTextBox.config(state=tk.DISABLED)
