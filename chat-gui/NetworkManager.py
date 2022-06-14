import json
import threading
import socket
import cryptoFunctions as crypt
from Crypto.Random import get_random_bytes
import rsa
from tqdm import tqdm
import os
import time
from base64 import b64encode
from base64 import b64decode

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

        # Message encryption

        msg = msg.encode(encoding='UTF-8')
        jsonEnc= self.parent.keyManager.encryptData(msg, sessionKey)
        json_data = json.loads(jsonEnc)
        encMsg = json_data['ciphertext']
        iv = None
        if self.parent.keyManager.cipherMode == "CBC":
            iv = json_data['iv']

        # Session key encryption
        encSessionKey = rsa.encrypt(sessionKey, self.parent.keyManager.otherPublicKey)
        encSessionKey = b64encode(encSessionKey).decode('utf-8')

        json_data = json.dumps(
            {'messageType': MessageType.casualMessage.value,
             'message': encMsg, 'encSessionKey': encSessionKey,
             'iv': iv
             })

        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        senderSocket.connect((self.destIP, self.destPort))
        senderSocket.sendall(json_data.encode())
        senderSocket.close()

    def sendFile(self, filepath):
        senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        senderSocket.connect((self.destIP, self.destPort))

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
        json_enc_data = self.parent.keyManager.encryptData(init_data, sessionKey)
        iv = None
        if self.parent.keyManager.cipherMode == "CBC":
            iv = json.loads(json_enc_data)['iv']

        # Session key encryption
        encSessionKey = rsa.encrypt(sessionKey, self.parent.keyManager.otherPublicKey)
        encSessionKey = b64encode(encSessionKey).decode('utf-8')

        crypt.writeBytes(f'encrypted_{filename}', bytes(json_enc_data, 'utf-8'))

        encryptedFile = f'encrypted_{filename}'
        print("encrypted File", encryptedFile)
        filesize = os.path.getsize(encryptedFile)
        print('filesize', filesize)
        json_data = json.dumps(
            {'messageType': MessageType.sendFile.value,
             'encSessionKey': encSessionKey,
             'format': formatFile,
             'size': filesize,
             'iv': iv
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

        os.remove(encryptedFile)
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
                data = conn.recv(SIZE)
                if not data:
                    break
                # data = data.decode()
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
                        self.parent.keyManager.cipherMode = data["cipherMode"]
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

                        # Decryption of the sessionKey
                        sessionKey = rsa.decrypt(b64decode(data['encSessionKey']),
                                                 self.parent.keyManager.ownPrivateKey)

                        # Decryption of the message
                        encMsg = data['message']
                        iv = None
                        if self.parent.keyManager.cipherMode == "CBC":
                            iv = data['iv']
                        
                        print(encMsg)
                        json_input = json.dumps({"ciphertext" : encMsg, "iv": iv})
                        msg = self.parent.keyManager.decryptData(json_input, sessionKey)
                        msg = msg.decode(encoding="UTF-8")

                        self.parent.showMessage(msg)

                    case MessageType.sendFile.value:
                        messageInfo = data
                        print(messageInfo)
                        # Progress BAR
                        bar = tqdm(range(messageInfo['size']), f"Receiving new file", unit="B", unit_scale=True,
                                   unit_divisor=SIZE)
                        recvFile = f"recv_file_encrypted.{messageInfo['format']}"
                        with open(recvFile, "wb") as f:
                            while True:
                                data = conn.recv(SIZE)
                                if not data:
                                    break
                                f.write(data)
                                bar.update(len(data))
                        # Decryption of the sessionKey
                        sessionKey = rsa.decrypt(b64decode(messageInfo['encSessionKey']),
                                                 self.parent.keyManager.ownPrivateKey)
                        # Decryption of the file
                        pathToSave = f"E:/Studia/Semestr 6/BSK/Security-of-Computer-Systems-Project-/chat-gui/recv_file_encrypted.{messageInfo['format']}"
                        fileToDecrypt = crypt.readBytes(recvFile)
                        dec_data = self.parent.keyManager.decryptData(fileToDecrypt, sessionKey)
                        crypt.writeBytes(pathToSave, dec_data)

            conn.close()
