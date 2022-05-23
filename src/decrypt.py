import argparse
import os
import bcrypt
from hashlib import sha256
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from questions import security_questions
from tqdm import tqdm
from util import load_pandora_data, load_rsa_key

def decrypt_account(account_aes, passphrase_hash):
    cipher_aes = AES.new(passphrase_hash[:16], AES.MODE_EAX, nonce=passphrase_hash[16:])
    try:
        account = cipher_aes.decrypt(b64decode(account_aes.encode('utf-8')))
        return account.decode()
    except:
        return "Incorrect decryption"

def main(private_key, encrypt_data):
    print("Answer the following questions to create AES key.")
    hashed_answers = security_questions()
    pandora_data = load_pandora_data(encrypt_data)
    rsa_object = load_rsa_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_object)
    
    print("Opening Pandora...")
    credentials = []
    for salt, account_aes, ciphertext, key in tqdm(pandora_data, desc="decrypting"):
        salt = salt.encode()
        passphrase_hash = sha256(bcrypt.hashpw(hashed_answers, salt)).digest()
        account_name = decrypt_account(account_aes, passphrase_hash)
        try:
            session_key_part1 = cipher_rsa.decrypt(b64decode(key.encode('utf-8')))
            session_key_part2, nonce = passphrase_hash[:16], passphrase_hash[16:]
            session_key = session_key_part1 + session_key_part2
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
            try:
                username, password = cipher_aes.decrypt(b64decode(ciphertext)).decode().split('|')
            except:
                username, password = "Incorrect decryption", "Incorrect decryption"
        except:
            username, password = "Incorrect decryption", "Incorrect decryption"
        
        credentials.append([account_name, username, password])
    
    credentials = sorted(credentials, key=lambda x:x[0])
    confirm = input("type open to confirm printing:  ")
    if confirm.lower().strip() == 'open':
        for account, username, passwd in credentials:
            print(f"Account: {account}\t Username:{username}\t Password:{passwd}")
    else:
        print("canceled.")
        
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='pandora decrypt script')
    parser.add_argument(
        "-k",
        "--rsa_private_key",
        default='',
        type=str,
        required=True,
        help="path to the rsa private key.",
    )
    args = parser.parse_args()
    if args and os.path.exists(args.rsa_private_key):
        main(private_key=args.rsa_private_key, encrypt_data='../data/pandora_data.bin')
    else:
        print("error, please check rsa private key file.")