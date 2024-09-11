from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aesLongKeyGen16 import *
import time
from ast import Bytes

# Function to read from a text file and append the lines in a list
def read_file(text_path):
    lines = []
    f = open(text_path,'r')
    for line in f:
        lines.append(line.rstrip())
    return lines

# Based on the 'if_encrypt', the function either ecrypts or decrypts the given text 
def get_encrypt_or_decrypt(byte_key, text, if_encrypt):
    short_key = bytearray(byte_key)
    long_key = expandKey(short_key)
    # setting up IV as a zero vector
    IV=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    cipher_object = Cipher(algorithms.AES(long_key), modes.CBC(IV))

    if if_encrypt:
        text_byte = text.encode('UTF-8')
        E_or_D_object = cipher_object.encryptor()
    else:
        text_byte = bytes.fromhex(text)
        E_or_D_object = cipher_object.decryptor()

    middle_cipher_text = E_or_D_object.update(text_byte) + E_or_D_object.finalize()
    middle_cipher_text_hex = middle_cipher_text.hex()
    return middle_cipher_text_hex

# Based on the 'if_encrypt', the function on a given text performs encryption or decryption using all the possible keys
def encrypt_decrypt_with_all_keys(text, if_encrypt):
    all_middle_cipher = {}
    all_middle_cipher_set = set()
    byte_size = 2

    for key in range(2**16):
        byte_key = key.to_bytes(byte_size, byteorder = 'big')
        middle_cipher_text_hex = get_encrypt_or_decrypt(byte_key, text, if_encrypt)
        # Store cipher-text key pair in dictionary for easy retrieval
        all_middle_cipher[middle_cipher_text_hex] = byte_key
        all_middle_cipher_set.add(middle_cipher_text_hex)
    
    return all_middle_cipher, all_middle_cipher_set

# For a given pair of candidate key this function verifies it for all the possible plain text cipher text pairs
def verify_keys(key_1, key_2, plain_text_list, cipher_text_list):
    key_check = True
    for i in range(1, len(plain_text_list)):
        middle_cipher_forward = get_encrypt_or_decrypt(key_1, plain_text_list[i], True)
        middle_cipher_backward = get_encrypt_or_decrypt(key_2, cipher_text_list[i], False)
        if middle_cipher_forward != middle_cipher_backward:
            key_check = False

    return key_check

# Function takes in list of plain texts and list of cipheer texts and return pair of keys if it exists
def man_in_the_middle_break(plain_text_list, cipher_text_list):
    plain_text = plain_text_list[0]
    cipher_text = cipher_text_list[0]
    all_middle_cipher, all_middle_cipher_set = encrypt_decrypt_with_all_keys(plain_text, True)
    all_middle_cipher_reverse, all_middle_cipher_set_reverse = encrypt_decrypt_with_all_keys(cipher_text, False)

    for cipher_text_one in all_middle_cipher_set:
        if cipher_text_one in all_middle_cipher_set_reverse:
            key_1 = all_middle_cipher[cipher_text_one]
            key_2 = all_middle_cipher_reverse[cipher_text_one]
            print('Candidate pair of key found')
            keys_check = verify_keys(key_1, key_2, plain_text_list, cipher_text_list)
            if keys_check:
                print('Successfully verified!')
                break
            
    if keys_check:
        return key_1, key_2
    else:
        return None, None

# Function to get secret message when the key pair is given
def get_secret_message(key_1, key_2, cipher_text):
    middle_cipher = get_encrypt_or_decrypt(key_2, cipher_text, False)
    secret_message = get_encrypt_or_decrypt(key_1, middle_cipher, False)
    secret_message_bytes = bytes.fromhex(secret_message)
    return str(secret_message_bytes.decode())

# Function saves the secret message in the text file '2aesSecretMessage.txt'
def save_secret_message(secret_message):
    f = open("2aesSecretMessage.txt","w")
    f.write(secret_message + "\n")
    f.close()

def main():
    plain_text_path = '2aesPlaintexts.txt'
    plain_text_list = read_file(plain_text_path)
    cipher_text_path = '2aesCiphertexts.txt'
    cipher_text_list = read_file(cipher_text_path)
    start_time = time.time()
    key_1, key_2 = man_in_the_middle_break(plain_text_list,cipher_text_list)
    if key_1 != None:
        print(f'Keys in byte    : {str(key_1)}, {str(key_2)}')
        print(f'Keys in hex     : {str(key_1.hex())}, {str(key_2.hex())}')
        secret_message = get_secret_message(key_1, key_2, cipher_text_list[-1])
        print(f'Secret message  : {secret_message}')
        save_secret_message(secret_message)
        end_time = time.time()
        print(f'Total time taken: {str(end_time-start_time)}')
    else:
        print('No key was found')

if __name__ == '__main__':
    main()
