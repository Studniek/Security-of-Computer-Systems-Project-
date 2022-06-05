import rsa
import os
from tkinter import filedialog
import keyExchange.EnterLocalKeyWindow as elkw

class KeyManager:
    def __init__(self, parent, publicKeysPath="keyExchange/public-keys/", privateKeysPath="keyExchange/private-keys/"):
        self.parent = parent  # Parent is the MainWindow

        self.publicKeysPath = publicKeysPath
        self.privateKeysPath = privateKeysPath

        self.ownPublicKey = None
        self.ownPrivateKey = None
        self.localKeyHash = None  # For encrypting private key

        self.otherPublicKey = None
        self.otherPrivateKey = None

    def generateRSAKeys(self, length=2048):
        print(self.localKeyHash)
        enterLocalKeyWindow = elkw.EnterLocalKeyWindow(self.parent)
        enterLocalKeyWindow.root.wait_window()

        print("LOLOLOL")
        print(self.localKeyHash)
        self.ownPublicKey, self.ownPrivateKey = rsa.newkeys(length)

        print(self.ownPublicKey)
        print(self.ownPrivateKey)
        # Need to cipher private key with hashed local key here before saving it to file....
        # ciphertext = cbc_encryption(self.ownPublicKey.save_pkcs1().decode('utf-8'), self.localKeyHash)
        # print(ciphertext)
        # plaintext = cbc_decryption(ciphertext)
        # print(plaintext)

        # PUBLIC KEY FILE
        publicKey_file = open(self.publicKeysPath + "ownPublic.pem", 'w+')
        publicKey_file.write(self.ownPublicKey.save_pkcs1().decode('utf-8'))
        publicKey_file.close()

        # PRIVATE KEY FILE
        privateKey_file = open(self.privateKeysPath + "ownPrivate.pem", 'w+')
        privateKey_file.write(self.ownPrivateKey.save_pkcs1().decode('utf-8'))
        privateKey_file.close()

    def loadRSAKeys(self):
        # PUBLIC KEY
        publicKey_path = filedialog.askopenfilename(initialdir="../chat-gui/keyExchange/public-keys/",
                                                    title="Select Public Key File")
        publicKey_file = open(publicKey_path, 'rb')
        publicKey = rsa.PublicKey.load_pkcs1(publicKey_file.read())
        publicKey_file.close()

        # PRIVATE KEY
        privateKey_path = filedialog.askopenfilename(initialdir="../chat-gui/keyExchange/private-keys/",
                                                     title="Select Private Key File")
        privateKey_file = open(privateKey_path, 'rb')
        privateKey = rsa.PrivateKey.load_pkcs1(privateKey_file.read())
        privateKey_file.close()
        # DECODING PRIVATE KEY WITH LOCAL KEY USING CBC HERE...

        print(publicKey)
        print(privateKey)

        return publicKey, privateKey
