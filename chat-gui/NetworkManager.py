import json
import threading
import socket
import cryptoFunctions as crypt
from Crypto.Random import get_random_bytes
import rsa
from tqdm import tqdm
import os
import time

from constants import *

SIZE = 1024

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

        self.parent.showMessage(msg)
        sessionKey = get_random_bytes(16)
        json_data = json.dumps(
            {'messageType': MessageType.casualMessage.value,
             'message': msg,'sessionKey': str(sessionKey)
             })

        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        senderSocket.connect((self.destIP, self.destPort))
        senderSocket.sendall(json_data.encode())
        senderSocket.close()

    def sendFile(self, filepath):
        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        senderSocket.connect((self.destIP,self.destPort))

        sessionKey = get_random_bytes(16)
        print(filepath)
        print(sessionKey)
        # sending a file
        filename = filepath.split("/")[-1]
        formatFile = filename.split(".")[-1]
        print(filename)
        print(formatFile)

        # encryption of the file
        init_data = crypt.readBytes(filepath)
        json_enc_data = crypt.ecbEncryption(init_data, sessionKey)
        crypt.writeBytes(f'encrypted_{filename}', bytes(json_enc_data, 'utf-8'))

        encryptedFile = f'encrypted_{filename}'
        print("encrypted File", encryptedFile)
        filesize = os.path.getsize(encryptedFile)
        print('filesize', filesize)
        json_data = json.dumps(
            {'messageType': MessageType.sendFile.value,
            'sessionKey': str(sessionKey),
            'format': formatFile,
            'size': filesize,
            })
        print("json data", json_data)
        senderSocket.send(json_data.encode())
        time.sleep(2)
        bar = tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=SIZE)
        print("tu mamy przesylanie")
        with open(encryptedFile, "rb") as f:
            while True:
                data = f.read(SIZE)
                if not data:
                    break
                senderSocket.send(data)
                bar.update(len(data))

        senderSocket.close()

    def sendHandshakeAnswer(self):
        publicRSAKey = self.parent.keyManager.ownPublicKey.save_pkcs1().decode('utf-8')
        msg = 'Wymiania kluczami publicznymi zakonczyla sie'

        json_data = json.dumps(
            {'messageType': MessageType.handshakeAnswer.value,
             'message': msg, 'publicRSAKey': publicRSAKey})

        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        senderSocket.connect(('127.0.0.1', self.destPort))
        senderSocket.sendall(json_data.encode())
        senderSocket.close()
        self.parent.showMessage(msg)

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
                #data = data.decode()
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
                    case MessageType.casualMessage.value:
                        self.parent.showMessage(data["message"])
                    case MessageType.sendFile.value:
                        messageInfo = data
                        print(messageInfo)
                        # Progress BAR
                        bar = tqdm(range(messageInfo['size']), f"Receiving new file", unit="B", unit_scale=True, unit_divisor=SIZE)
                        recvFile = f"recv_file_encrypted.{messageInfo['format']}"
                        with open(recvFile, "wb") as f:
                            while True:
                                data = conn.recv(SIZE)
                                if not data:
                                    break
                                f.write(data)
                                bar.update(len(data))
                        
                        pathToSave = f"E:/Studia/Semestr 6/BSK/Security-of-Computer-Systems-Project-/chat-gui/recv_file_encrypted.{messageInfo['format']}"
                        fileToDecrypt = crypt.readBytes(recvFile)
                        dec_data = crypt.ecbDecryption(fileToDecrypt,bytes(messageInfo['sessionKey'],'utf-8'))
                        crypt.writeBytes(pathToSave,dec_data)


            conn.close()
