import rsa
import os



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
        self.ownPublicKey, self.ownPrivateKey = rsa.newkeys(length)

        print(self.ownPublicKey)
        print(self.ownPrivateKey)
        # Need to cipher private key with hashed local key here before saving it to file....
        ciphertext = cbc_encryption(self.ownPublicKey.save_pkcs1().decode('utf-8'), self.localKeyHash)
        print(ciphertext)
        plaintext = cbc_decryption(ciphertext)
        print(plaintext)

        # PUBLIC KEY FILE
        publicKey_file = open(self.publicKeysPath + "ownPublic.pem", 'w+')
        publicKey_file.write(self.ownPublicKey.save_pkcs1().decode('utf-8'))
        publicKey_file.close()

        # PRIVATE KEY FILE
        privateKey_file = open(self.privateKeysPath + "ownPrivate.pem", 'w+')
        privateKey_file.write(self.ownPrivateKey.save_pkcs1().decode('utf-8'))
        privateKey_file.close()
