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

        self.ownPublicKey, self.ownPrivateKey = rsa.newkeys(256)
        #self.ownPublicKey = None
        #self.ownPrivateKey = None
        self.localKeyHash = None  # For encrypting private key

        self.otherPublicKey = None
        self.sessionKey = None

    def generateRSAKeys(self, length=256):
        # LOCAL KEY
        enterLocalKeyWindow = elkw.EnterLocalKeyWindow(self.parent)
        enterLocalKeyWindow.root.wait_window()

        # RSA KEYS GENERATION
        self.ownPublicKey, self.ownPrivateKey = rsa.newkeys(length)

        # RSA KEYS CIPHERING
        encodedPublicKey = cbcEncryption(self.ownPublicKey.save_pkcs1(), self.localKeyHash)
        decodedPublicKey = cbcDecryption(encodedPublicKey, self.localKeyHash)
        print("Public Key:")
        print(self.ownPublicKey)
        print(encodedPublicKey)
        print(decodedPublicKey)

        encodedPrivateKey = cbcEncryption(self.ownPrivateKey.save_pkcs1(), self.localKeyHash)
        decodedPrivateKey = cbcDecryption(encodedPrivateKey, self.localKeyHash)
        print("Private Key:")
        print(self.ownPrivateKey)
        print(encodedPrivateKey)
        print(decodedPrivateKey)
        print("\n\n\n")

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
        print("Public Key:")
        print(rsa.PublicKey.load_pkcs1(decodedPublicKey))
        print(encodedPublicKey)
        print(decodedPublicKey)

        # PRIVATE KEY
        privateKey_file = open(privateKey_path, 'rb')
        encodedPrivateKey = json.dumps(json.load(privateKey_file))
        decodedPrivateKey = cbcDecryption(encodedPrivateKey, self.localKeyHash)
        privateKey_file.close()
        print("Private Key:")
        # print(rsa.PrivateKey.load_pkcs1(decodedPrivateKey))
        print(encodedPrivateKey)
        print(decodedPrivateKey)

        try:
            decodedPublicKey = rsa.PublicKey.load_pkcs1(decodedPublicKey)
            decodedPrivateKey = rsa.PrivateKey.load_pkcs1(decodedPrivateKey)
            self.ownPublicKey = decodedPublicKey
            self.ownPrivateKey = decodedPrivateKey
        except AttributeError:
            print("Incorrect decryption")

        return decodedPublicKey, decodedPrivateKey
