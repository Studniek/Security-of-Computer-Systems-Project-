import CreateChatWindow as ccw
from constants import *
import tkinter as tk
import threading
import socket
from tkinter import filedialog


class MainWindow:
    def __init__(self, listenerPort, senderPort, title):
        self.listener = threading.Thread(target=self.listenFunction, daemon=True)
        self.listener.start()
        self.listenerPort = int(listenerPort)
        self.senderPort = int(senderPort)

        self.destIP = ""
        self.destPort = -1

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


        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("jestesmy w sendMessage")
        print("send1",self.destIP)
        print("send2",self.destPort)
        
        senderSocket.connect((self.destIP,self.destPort))
        senderSocket.send(msg.encode())

        senderSocket.close()

    def showMessage(self, msg):
        self.chatTextBox.config(state=tk.NORMAL)
        self.chatTextBox.insert(tk.INSERT, msg)
        self.chatTextBox.config(state=tk.DISABLED)

    def clearChat(self):
        self.chatTextBox.config(state=tk.NORMAL)
        self.chatTextBox.delete('1.0', tk.END)
        self.chatTextBox.config(state=tk.DISABLED)

    def listenFunction(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', self.listenerPort))
        sock.listen()


        while True:
            conn, senderInfo = sock.accept()
            print("Listener Function")
            print("conn", conn)
            print("senderInfo", senderInfo)

            while True:
                data = conn.recv(1024)
                if not data:
                    break
                msg = data.decode()
                #print(msg)
                if self.destPort == -1:
                    senderAddr, senderPort = senderInfo
                    print("senderAddr",senderAddr)
                    print("senderPort",senderPort)
                    self.destIP = senderAddr
                    self.destPort = int(msg.split(";")[0])
                self.showMessage(msg)
            conn.close()
