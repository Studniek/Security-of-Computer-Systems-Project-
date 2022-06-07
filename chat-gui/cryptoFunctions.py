import os
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from random import random
from PIL import Image
import io


def readBytes(filepath):
    file = open(filepath, "rb")
    data = file.read()
    file.close()
    return data


def writeBytes(filepath, data):
    file = open(filepath, "wb")
    file.write(data)
    file.close()
    
def getDataFromJSON(jsonData):
    b64 = json.loads(jsonData)
    enc_data = b64decode(b64['ciphertext'])
    return enc_data

def generate_key(key_length):
    return get_random_bytes(key_length)

def ecbEncryption(data, key, view_data=False):
    cipher = AES.new(key, AES.MODE_ECB)
    enc_data = cipher.encrypt(pad(data, AES.block_size))
    ct = b64encode(enc_data).decode('utf-8')
    key = b64encode(key).decode('utf-8')
    json_data = json.dumps({'key': key,'ciphertext': ct})
    if view_data:
        print("Encrypted data:\n" + json_data)
    return json_data


def ecbDecryption(json_data,view_data=False):
    try:
        b64 = json.loads(json_data)
        enc_data = b64decode(b64['ciphertext'])
        key = b64decode(b64['key'])
        # # Change 1 byte in ciphertext
        # # 1 Block (in which 1 changed byte located) is changed in decrypted data
        # enc_data = bytearray(enc_data)
        # enc_data[0] = 123

        cipher = AES.new(key, AES.MODE_ECB)
        dec_data = unpad(cipher.decrypt(enc_data), AES.block_size)
        if view_data:
            print("Decrypted data: ", str(dec_data))
        return dec_data
    except (ValueError, KeyError) as e:
        print("Incorrect decryption")


def cbcEncryption(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    key = b64encode(key).decode('utf-8')
    result = json.dumps({'iv': iv,'key': key, 'ciphertext': ct})
    return result


def cbcDecryption(json_input):
    try:
        b64 = json.loads(json_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        key = b64decode(b64['key'])
        # mini komenatrz jednolinijkowy
        #ct = bytearray(ct)
        #ct[0] = 13
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        #print("The message was: ", pt)
        return pt
    except ValueError:
        print("Incorrect decryption")
