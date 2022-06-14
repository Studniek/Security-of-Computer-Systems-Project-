import rsa
import os
from tkinter import filedialog
import EnterLocalKeyWindow as elkw
from cryptoFunctions import *


class KeyManager:
    def __init__(self, parent, publicKeysPath="public-keys/", privateKeysPath="private-keys/"):
        self.parent = parent  # Parent is the MainWindow

        self.publicKeysPath = publicKeysPath
        self.privateKeysPath = privateKeysPath

        self.ownPublicKey = None
        self.ownPrivateKey = None
        self.localKeyHash = None  # For encrypting private key

        self.cipherMode = None

        self.otherPublicKey = None
        self.sessionKey = None

    def encryptData(self,data, key):
        if self.cipherMode == "ECB":
            return ecbEncryption(data, key)
        elif self.cipherMode == "CBC":
            return cbcEncryption(data, key)
        else:
            print("Bad Cipher Mode")
            return -1

    def decryptData(self,data, key):
        if self.cipherMode == "ECB":
            return ecbDecryption(data, key)
        elif self.cipherMode == "CBC":
            return cbcDecryption(data, key)
        else:
            print("Bad Cipher Mode")
            return -1



    def generateRSAKeys(self, length=2048):
        # LOCAL KEY
        enterLocalKeyWindow = elkw.EnterLocalKeyWindow(self.parent)
        enterLocalKeyWindow.root.wait_window()

        # RSA KEYS GENERATION
        self.ownPublicKey, self.ownPrivateKey = rsa.newkeys(length)

        # RSA KEYS CIPHERING
        encodedPublicKey = cbcEncryption(self.ownPublicKey.save_pkcs1(), self.localKeyHash)
        decodedPublicKey = cbcDecryption(encodedPublicKey, self.localKeyHash)

        encodedPrivateKey = cbcEncryption(self.ownPrivateKey.save_pkcs1(), self.localKeyHash)
        decodedPrivateKey = cbcDecryption(encodedPrivateKey, self.localKeyHash)

        # PUBLIC KEY FILE
        publicKey_file = open(self.publicKeysPath + "ownPublic2.json", 'w')
        publicKey_file.write(encodedPublicKey)
        publicKey_file.close()

        # PRIVATE KEY FILE
        privateKey_file = open(self.privateKeysPath + "ownPrivate2.json", 'w')
        privateKey_file.write(encodedPrivateKey)
        privateKey_file.close()

    def loadRSAKeys(self):
        publicKey_path = filedialog.askopenfilename(initialdir="../chat-gui/public-keys/",
                                                    title="Select Public Key File")
        privateKey_path = filedialog.askopenfilename(initialdir="../chat-gui/private-keys/",
                                                     title="Select Private Key File")
        # LOCAL KEY
        enterLocalKeyWindow = elkw.EnterLocalKeyWindow(self.parent)
        enterLocalKeyWindow.root.wait_window()

        # PUBLIC KEY
        publicKey_file = open(publicKey_path, 'rb')
        encodedPublicKey = json.dumps(json.load(publicKey_file))
        decodedPublicKey = cbcDecryption(encodedPublicKey, self.localKeyHash)
        publicKey_file.close()

        # PRIVATE KEY
        privateKey_file = open(privateKey_path, 'rb')
        encodedPrivateKey = json.dumps(json.load(privateKey_file))
        decodedPrivateKey = cbcDecryption(encodedPrivateKey, self.localKeyHash)
        privateKey_file.close()

        try:
            decodedPublicKey = rsa.PublicKey.load_pkcs1(decodedPublicKey)
            decodedPrivateKey = rsa.PrivateKey.load_pkcs1(decodedPrivateKey)
            self.ownPublicKey = decodedPublicKey
            self.ownPrivateKey = decodedPrivateKey
        except AttributeError:
            print("Incorrect decryption")

        return decodedPublicKey, decodedPrivateKey
