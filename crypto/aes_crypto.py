from Crypto.Cipher import AES
import hashlib

def qkd_to_aes_key(qkd_key):
    # Convert QKD bit string to AES-256 key
    key_str = ''.join(map(str, qkd_key))
    return hashlib.sha256(key_str.encode()).digest()

def encrypt_file(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ciphertext + tag

def decrypt_file(enc_data, aes_key):
    nonce = enc_data[:16]
    tag = enc_data[-16:]
    ciphertext = enc_data[16:-16]

    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
def decrypt_file(enc_data, aes_key):
    nonce = enc_data[:16]
    tag = enc_data[-16:]
    ciphertext = enc_data[16:-16]

    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
