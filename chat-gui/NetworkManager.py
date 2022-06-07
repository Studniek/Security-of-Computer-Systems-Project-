import json
import threading
import socket

import rsa

from constants import *


class NetworkManager:
    def __init__(self, parent, listenerPort=5050, senderPort=5051):
        self.parent = parent  # Parent is the MainWindow
        self.listener = threading.Thread(target=self.listenFunction, daemon=True)
        self.listener.start()
        self.listenerPort = int(listenerPort)
        self.senderPort = int(senderPort)
        self.destIP = ""
        self.destPort = -1

    def sendMessage(self, msg):
        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # json_data = json.dumps({'messageType':, 'ciphertext': ct})
        print("jestesmy w sendMessage")
        print("send1", self.destIP)
        print("send2", self.destPort)

        senderSocket.connect((self.destIP, self.destPort))
        senderSocket.send(msg.encode())
        senderSocket.close()

    def sendHandshakeAnswer(self):
        publicRSAKey = self.parent.keyManager.ownPublicKey.save_pkcs1().decode('utf-8')
        msg = 'Wymiania kluczami publicznymi zakonczyla sie'

        json_data = json.dumps(
            {'messageType': MessageType.handshakeAnswer.value,
             'message': msg, 'publicRSAKey': publicRSAKey})

        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        senderSocket.connect(('127.0.0.1', self.parent.networkManager.destPort))
        senderSocket.sendall(json_data.encode())
        senderSocket.close()

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

                data = json.loads(data)
                messageType = data["messageType"]
                print(data)

                match messageType:
                    case MessageType.handshake.value:
                        senderAddr, senderPort = senderInfo
                        print("senderAddr", senderAddr)
                        print("senderPort", senderPort)
                        self.destIP = senderAddr
                        self.destPort = data["destinationPort"]
                        self.parent.showMessage(data["message"])
                        # Wymiana kluczy
                        otherRSAPublicKey = bytes(data["publicRSAKey"], 'utf-8')
                        self.parent.keyManager.otherPublicKey = rsa.PublicKey.load_pkcs1(otherRSAPublicKey)
                        print(self.parent.keyManager.otherPublicKey)
                        self.sendHandshakeAnswer()

                    case MessageType.handshakeAnswer.value:
                        # Wymiana kluczy
                        otherRSAPublicKey = bytes(data["publicRSAKey"], 'utf-8')
                        self.parent.keyManager.otherPublicKey = rsa.PublicKey.load_pkcs1(otherRSAPublicKey)
                        self.parent.showMessage(data["message"])
                        print(self.parent.keyManager.otherPublicKey)

                # case MessageType.casualMessage:
                # case MessageType.file:

            conn.close()
