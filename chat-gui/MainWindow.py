import CreateChatWindow as ccw
# import constants as consts
from constants import *
import tkinter as tk
import threading
import socket
from tkinter import filedialog


class MainWindow:
    def __init__(self, title):
        self.listener = threading.Thread(target=self.listenFunction, daemon=True)
        self.listener.start()

        self.root = tk.Tk()
        self.root.title(title)

        self.canvas = tk.Canvas(self.root, height=WINDOW_HEIGHT, width=WINDOW_WIDTH,
                                bg=WINDOWS_BG_COLOR)
        self.canvas.pack()

        self.frame = tk.Frame(self.root, bg="white")
        self.frame.place(relwidth=0.8, relheight=0.8, relx=0.1, rely=0.1)

        self.chatLabel = tk.Label(self.frame, text="Chat window")
        self.chatTextBox = tk.Text(self.frame, bg="light blue", width=80, height=25, state='disabled')
        self.createChatButton = tk.Button(self.root, text="Create Chat", padx=10, pady=5,
                                          fg="white", bg=WINDOWS_BG_COLOR,
                                          command=lambda: ccw.CreateChatWindow(self))
        self.clearChatButton = tk.Button(self.frame, text="Clear chat", padx=10, pady=5,
                                         fg="white", bg=WINDOWS_BG_COLOR, command=self.clearChat)

        self.enterMessageLabel = tk.Label(self.frame, text="Enter your message")
        self.enterMessageTextBox = tk.Text(self.frame, bg="light blue", width=50, height=2)
        self.sendMessageButton = tk.Button(self.frame, text="Send your message", padx=10, pady=5,
                                           fg="white", bg=WINDOWS_BG_COLOR, command=self.sendMessage)

        self.addFileButton = tk.Button(self.frame, text="Add File", padx=10, pady=5,
                                       fg="white", bg=WINDOWS_BG_COLOR, command=self.addFile)

        self.createChatButton.pack()
        self.chatLabel.pack()
        self.chatTextBox.pack()
        self.enterMessageLabel.pack()
        self.enterMessageTextBox.pack()
        self.sendMessageButton.pack()
        self.clearChatButton.pack()
        self.addFileButton.pack()

        self.root.mainloop()

    def addFile(self):
        filenames = filedialog.askopenfilenames(initialdir="/", title="Select File")
        for filename in filenames:
            # LOADING FILES TO MEMORY AND SENDING THEM TO ANOTHER USER HERE...
            print(filename)

    def sendMessage(self):
        msg = self.enterMessageTextBox.get("1.0", tk.END)
        self.chatTextBox.config(state=tk.NORMAL)
        self.chatTextBox.insert(tk.INSERT, msg)
        self.chatTextBox.config(state=tk.DISABLED)

    def clearChat(self):
        self.chatTextBox.config(state=tk.NORMAL)
        self.chatTextBox.delete('1.0', tk.END)
        self.chatTextBox.config(state=tk.DISABLED)

    def listenFunction(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', LISTENER_PORT))

        while True:
            data = sock.recv(1024)
            print('\rpeer: {}\n> '.format(data.decode()), end='')
