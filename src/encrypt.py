import getpass
import bcrypt
from base64 import b64encode
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from questions import security_questions
from util import load_pandora_data, rsa_encrypt, save_pandora_data

def encrypt_input(cipher_aes):
    username = input('Username: ')
    password = getpass.getpass('Password: ')
    ciphertext = cipher_aes.encrypt('|'.join([username,password]).encode('utf-8'))
    return b64encode(ciphertext).decode('utf-8')


def find_account(account, hashed_answers, pandora_data):
    print("search account info...")
    for i, data in enumerate(pandora_data):
        salt, ciphertext = data[:2]
        salt = salt.encode()
        passphrase_hash = sha256(bcrypt.hashpw(hashed_answers, salt)).digest()
        cipher_aes = AES.new(passphrase_hash[:16], AES.MODE_EAX, nonce=passphrase_hash[16:])
        account_aes = b64encode(cipher_aes.encrypt(account)).decode('utf-8')
        if account_aes == ciphertext:
            return i
    return -1

def encrypt_account(account, passphrase_hash):
    cipher_aes = AES.new(passphrase_hash[:16], AES.MODE_EAX, nonce=passphrase_hash[16:])
    account_aes = b64encode(cipher_aes.encrypt(account)).decode('utf-8')
    return account_aes


def main(public_key, encrypt_data):
    account = input('Account info: ').encode('utf-8')
    action = input('Action(create|update|delete): ')
    assert action in ['create', 'update', 'delete'], 'operation not recognized.'
    
    print("Answer the following questions to create AES key.")
    hashed_answers = security_questions()
    pandora_data = load_pandora_data(encrypt_data)
    index = find_account(account, hashed_answers, pandora_data)

    if action == 'delete':
        if index != -1:
            pandora_data.pop(index)
            save_pandora_data(pandora_data, encrypt_data)
            print('Account removed.')
        else:
            print('Account not found in Pandora data.')
    else:
        salt = bcrypt.gensalt()
        passphrase_hash = sha256(bcrypt.hashpw(hashed_answers, salt)).digest()
        account_aes = encrypt_account(account, passphrase_hash)
        session_key_part1 = get_random_bytes(16)
        session_key_part2, nonce = passphrase_hash[:16], passphrase_hash[16:]
        session_key = session_key_part1 + session_key_part2
        encrypt_session_data = b64encode(rsa_encrypt(public_key, session_key_part1)).decode('utf-8')
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
        salt = salt.decode('utf-8')
        if action == 'create':
            if index == -1:
                ciphertext = encrypt_input(cipher_aes)
                new_record = [salt, account_aes, ciphertext, encrypt_session_data]
                pandora_data.append(new_record)
                save_pandora_data(pandora_data, encrypt_data)
                print('Account added.')
            else:
                print('Account already exists Pandora data.')
        else:
            if index > -1:
                ciphertext = encrypt_input(cipher_aes)
                new_record = [salt, account_aes, ciphertext, encrypt_session_data]
                pandora_data[index] = new_record
                save_pandora_data(pandora_data, encrypt_data)
                print('Account updated.')
            else:
                print('Account not found in Pandora data.')

if __name__ == '__main__':
    main(public_key='../data/pandora_public.pem', encrypt_data='../data/pandora_data.bin')