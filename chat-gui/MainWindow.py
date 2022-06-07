import CreateChatWindow as ccw
from constants import *
import tkinter as tk
from tkinter.ttk import Progressbar
import threading
import socket
import os
from tqdm import tqdm
from tkinter import filedialog
from keyExchange import KeyManager as km
import cryptoFunctions as crypt


SIZE = 1024
FORMAT = "utf-8"

class MainWindow:
    def __init__(self, listenerPort=5050, senderPort=5051, title="BSK: Secure p2p chat"):

        # NETWORK
        self.listener = threading.Thread(target=self.listenFunction, daemon=True)
        self.listener.start()
        self.listenerPort = int(listenerPort)
        self.senderPort = int(senderPort)
        self.destIP = ""
        self.destPort = -1

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
                                           fg="white", bg=WINDOWS_BG_COLOR, command=self.sendMessage)

        self.addFileButton = tk.Button(self.frame, text="Add File", padx=10, pady=5,
                                       fg="white", bg=WINDOWS_BG_COLOR, command=self.addFile)

        self.generateKeysButton = tk.Button(self.frame, text="Generate RSA Keys", padx=10, pady=5,
                                            fg="white", bg=WINDOWS_BG_COLOR,
                                            command= self.keyManager.generateRSAKeys)

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
        filenames = filedialog.askopenfilenames(initialdir="E:/Studia/Semestr 6/BSK/Security-of-Computer-Systems-Project-/chat-gui", title="Select File")
        filepath= filenames[0]
        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        senderSocket.connect((self.destIP,self.destPort))
        # Sending name of the file with flag that it is a file
        fileFlag = "file"
        filename = filepath.split("/")[-1]

        # encryption of the file 
        key = crypt.get_random_bytes(16)
        init_data = crypt.readBytes(filepath)
        json_enc_data = crypt.ecbEncryption(init_data, key)
        crypt.writeBytes(filename, bytes(json_enc_data, 'utf-8'))


        filesize = os.path.getsize(filepath)
        fileInfo = f"{fileFlag}_{filename}_{filesize}"

        print("fileInfo",fileInfo)

        senderSocket.send(fileInfo.encode(FORMAT))
        print("fileName",filename)

        #Create progressBar
        # pbWindow = tk.Tk()
        # pbWindow.title("ProgressBar")
        # pbWindow.geometry("500x500")

        # pb = Progressbar(
        #     pbWindow,
        #     orient = "horizontal",
        #     length = 100,
        #     mode = 'determinate'
        # )
        # pb.place(x=40, y=20)
        # txt = tk.Label(
        #     pbWindow,
        #     text = '0%',
        #     bg = '#345',
        #     fg = '#fff'
        # )
        # txt.place(x=150 ,y=20 )
        # tk.Button(
        #     pbWindow,
        #     text='Close',
        #     command= lambda: pbWindow.destroy()
        # ).place(x=40, y=50)
        # #pbWindow.mainloop()
        print("poszło dalej")
        bar = tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=SIZE)
        #filename
        with open(filename, "rb") as f:
            while True:
                data = f.read(SIZE)
                if not data:
                    break
                senderSocket.send(data)
                bar.update(len(data))

        # closing the connection
        senderSocket.close()

    def sendMessage(self):
        msg = self.enterMessageTextBox.get("1.0", tk.END)
        self.chatTextBox.config(state=tk.NORMAL)
        self.chatTextBox.insert(tk.INSERT, msg)
        self.chatTextBox.config(state=tk.DISABLED)

        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("jestesmy w sendMessage")
        print("send1", self.destIP)
        print("send2", self.destPort)

        senderSocket.connect((self.destIP, self.destPort))
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
                data = conn.recv(200)
                if not data:
                    break
                msg = data.decode(FORMAT)
                print(msg)
                if msg.split("_")[0] == "file":
                    print("msg2",msg)
                    fileName = msg.split("_")[1]
                    fileSize = msg.split("_")[2]

                    # Progress BAR
                    bar = Progressbar(self.root, orient='horizontal', length = 100, mode ='determinate')
                    bar.pack(expand = True)

                    with open(f"recv_{fileName}", "wb") as f:

                        while True:
                            data = conn.recv(SIZE)
                            if not data:
                                break
                            f.write(data)  
            
                #print(msg)
                if self.destPort == -1:
                    senderAddr, senderPort = senderInfo
                    print("senderAddr", senderAddr)
                    print("senderPort", senderPort)
                    self.destIP = senderAddr
                    self.destPort = int(msg.split(";")[0])
                self.showMessage(msg)

            conn.close()
