import argparse
import os
import json
from base64 import b64decode
from Crypto.PublicKey import RSA # type: ignore
from Crypto.Cipher import AES, PKCS1_OAEP # type: ignore
from tqdm import tqdm # type: ignore
from util import load_pandora_jsonl

def main(private_key, encrypt_data):
    pandora_data = load_pandora_jsonl(encrypt_data)
    private_key = RSA.import_key(open(private_key).read())
    
    pandora_accounts = [record["account"] for record in pandora_data]
    print("Pandora Box has the following accounts:")
    print(sorted(pandora_accounts))

    query = input("Account (type all to list all credentials): ")
    if query not in pandora_accounts and query != "all":
        print("Account not found in Pandora Box.")
    elif query in pandora_accounts:
        credentials = []
        index = pandora_accounts.index(query)
        item = pandora_data[index]
        account = item["account"]
        cipher_chunks = item["ciphertext"].split()
        try:
            ciphertext_bytes = [b64decode(chunk.encode('utf-8')) for chunk in cipher_chunks]
            enc_session_key, nonce, tag, ciphertext = ciphertext_bytes
            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            creds = cipher_aes.decrypt_and_verify(ciphertext, tag)
            username, password = creds.decode().split('|')
        except:
            username, password = "Incorrect decryption", "Incorrect decryption"
        credentials.append({"account":query, "username": username, "password": password})
        json_formatted_str = json.dumps(credentials, indent=4)
        print(json_formatted_str)
    else:
        credentials = []
        for item in tqdm(pandora_data, desc="decrypting"):
            account = item["account"]
            cipher_chunks = item["ciphertext"].split()
            try:
                ciphertext_bytes = [b64decode(chunk.encode('utf-8')) for chunk in cipher_chunks]
                enc_session_key, nonce, tag, ciphertext = ciphertext_bytes
                cipher_rsa = PKCS1_OAEP.new(private_key)
                session_key = cipher_rsa.decrypt(enc_session_key)
                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                creds = cipher_aes.decrypt_and_verify(ciphertext, tag)
                username, password = creds.decode().split('|')
            except:
                username, password = "Incorrect decryption", "Incorrect decryption"
            credentials.append({"account":account, "username": username, "password": password})
        
        credentials = sorted(credentials, key=lambda x: x["account"])
        confirm = input("type open to confirm printing:  ")
        if confirm.lower().strip() == 'open':
            json_formatted_str = json.dumps(credentials, indent=4)
            print(json_formatted_str)
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