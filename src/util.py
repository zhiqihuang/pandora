from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import getpass

def load_rsa_key(path):
    with open(path, mode='rb') as keyfile:
        keydata = keyfile.read()
    return RSA.import_key(keydata)

def rsa_encrypt(path, data):
    rsa_object = load_rsa_key(path)
    cipher_rsa = PKCS1_OAEP.new(rsa_object)
    return cipher_rsa.encrypt(data)

def load_pandora_data(path):
    f = open(path,'r')
    pandora_data = [x.split('\t') for x in f.read().splitlines()]
    f.close()
    return pandora_data

def save_pandora_data(pandora_data, path):
    f = open(path,'w')
    for data in pandora_data:
        f.write("""\t""".join(data))
        f.write("\n")
    f.close()

