import rsa
import os
from tkinter import filedialog
import threading
import socket


class NetworkManager:
    def __init__(self, parent, listenerPort=5050, senderPort=5051):
        self.parent = parent  # Parent is the MainWindow
        self.listener = threading.Thread(target=self.listenFunction, daemon=True)
        self.listener.start()
        self.listenerPort = int(listenerPort)
        self.senderPort = int(senderPort)
        self.destIP = ""
        self.destPort = -1

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
                # print(msg)
                if self.destPort == -1:
                    senderAddr, senderPort = senderInfo
                    print("senderAddr", senderAddr)
                    print("senderPort", senderPort)
                    self.destIP = senderAddr
                    self.destPort = int(msg.split(";")[0])
                self.parent.showMessage(msg)
            conn.close()
