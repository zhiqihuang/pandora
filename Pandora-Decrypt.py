
# coding: utf-8

# In[1]:
#pycrypto==2.6.1 !important, the method might change between versions
import Crypto #important
from Crypto.Cipher import AES
import hashlib
import getpass
import os
import random
import base64
from Crypto.PublicKey import RSA


# In[2]:
key_name = 'RSA-PrivateKey.txt'
path = raw_input("private key localtion: ")
private_key_location = os.path.join(path, key_name)
aes_key = getpass.getpass('AES Key: ').encode('utf-8')
f = open(private_key_location,'r')
private = f.read()
f.close()
f = open('pandora.txt','r')
pw_list = f.read().splitlines() 
f.close()


# In[12]:

def decode(private,aes_key,pw_list):
    private_key = RSA.importKey(private)
    md = hashlib.md5()
    md.update(aes_key)
    aes_string = md.digest()
    obj = AES.new(aes_string)
    pandora = []
    for string in pw_list:
        account = private_key.decrypt(obj.decrypt(base64.b64decode(string.split('\t')[0])))
        login = private_key.decrypt(obj.decrypt(base64.b64decode(string.split('\t')[1])))
        pandora.append([account,login])
    return pandora


# In[16]:

pandora = decode(private,aes_key,pw_list)
print "!!Warning!! Pandora is opened"

while(1):
    opt = raw_input("save or print: ")
    if opt == 'save':
        print "saved to the same dirctory with private key. !!Delete after viewing!!"
        f=open('/'.join(private_key_location.split('/')[0:(len(private_key_location.split('/'))-1)])+'/pandora-opened.txt','w')
        for i in pandora:
            f.write("""%s,%s\n"""%(i[0],i[1]))
        f.close()
        break
    elif opt == 'print':
        for i in pandora:
            print i
        break

