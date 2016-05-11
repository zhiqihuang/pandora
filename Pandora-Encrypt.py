
# coding: utf-8

# In[1]:

from Crypto.Cipher import AES
import hashlib
import getpass
import random
import base64
from Crypto.PublicKey import RSA


# In[2]:

f = open('RSA-PublicKey.txt','r')
public = f.read()
account = raw_input('account info: ').encode('utf-8')
username = raw_input('username: ').encode('utf-8')
password = getpass.getpass('password: ').encode('utf-8')
aes_key = getpass.getpass('AES Key: ').encode('utf-8')
init_string = '|'.join([account,username,password]).encode('utf-8')


# In[7]:

def encode(public,aes_key,init_string):
    public_key = RSA.importKey(public)
    md = hashlib.md5()
    md.update(aes_key)
    aes_string = md.digest()
    rsa_encoded = public_key.encrypt(init_string,random.randint(0,1990))[0]
    obj = AES.new(aes_string)
    return obj.encrypt(rsa_encoded)


# In[8]:

encoded = base64.b64encode(encode(public,aes_key,init_string))
f = open('pandora.txt','a')
f.write("""%s"""%encoded)
f.write("\n")
f.close()
print 'Encrypt into Pandora!'

