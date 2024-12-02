from Crypto.PublicKey import RSA # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
from Crypto.Cipher import AES, PKCS1_OAEP # type: ignore
import getpass
from base64 import b64encode
from util import load_pandora_jsonl, save_pandora_jsonl

def encrypt_input(cipher_aes):
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    ciphertext, tag = cipher_aes.encrypt_and_digest("|".join([username,password]).encode("utf-8"))
    return ciphertext, tag

def bytes_to_str(data):
    return b64encode(data).decode("utf-8")

def main(public_key, encrypt_data):
    
    pandora_data = load_pandora_jsonl(encrypt_data)
    pandora_accounts = [record["account"] for record in pandora_data]
    print("Pandora Box has the following accounts:")
    print(sorted(pandora_accounts))
    
    account = input("Account info: ")
    action = input("Action(create|update|delete): ")
    assert action in ["create", "update", "delete"], "operation not recognized."
    has_account = account in pandora_accounts
    
    recipient_key = RSA.import_key(open(public_key).read())
    session_key = get_random_bytes(16)
    
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    
    if action == "delete":
        if has_account:
            index = pandora_accounts.index(account)
            pandora_data.pop(index)
            save_pandora_jsonl(pandora_data, encrypt_data)
            print("Account removed.")
        else:
            print("Account not found in Pandora Box.")
    else:
        if action == "create":
            if not has_account:
                ciphertext, tag = encrypt_input(cipher_aes)
                new_record = {"account": account, "ciphertext": " ".join([bytes_to_str(enc_session_key), bytes_to_str(cipher_aes.nonce), bytes_to_str(tag), bytes_to_str(ciphertext)])}
                pandora_data.append(new_record)
                save_pandora_jsonl(pandora_data, encrypt_data)
                print("Account added.")
            else:
                print("Account already exists in Pandora Box.")
        else:
            if has_account:
                ciphertext, tag = encrypt_input(cipher_aes)
                new_record = " ".join([bytes_to_str(enc_session_key), bytes_to_str(cipher_aes.nonce), bytes_to_str(tag), bytes_to_str(ciphertext)])
                index = pandora_accounts.index(account)
                assert pandora_data[index]["account"] == account, "account mismatch."
                pandora_data[index]["ciphertext"] = new_record
                save_pandora_jsonl(pandora_data, encrypt_data)
                print("Account updated.")
            else:
                print("Account not found in Pandora Box.")

if __name__ == "__main__":
    main(public_key="../data/pandora_public.pem", encrypt_data="../data/pandora_data_v2.bin")