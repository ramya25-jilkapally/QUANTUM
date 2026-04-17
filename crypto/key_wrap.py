from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

SALT_SIZE = 16


def wrap_key_with_password(aes_key, password):

    salt = os.urandom(SALT_SIZE)

    derived_key = PBKDF2(password, salt, dkLen=32)

    cipher = AES.new(derived_key, AES.MODE_CBC)

    encrypted_key = cipher.encrypt(pad(aes_key, 16))

    return salt + cipher.iv + encrypted_key


def unwrap_key_with_password(wrapped_key, password):

    salt = wrapped_key[:16]
    iv = wrapped_key[16:32]
    encrypted_key = wrapped_key[32:]

    derived_key = PBKDF2(password, salt, dkLen=32)

    cipher = AES.new(derived_key, AES.MODE_CBC, iv)

    aes_key = unpad(cipher.decrypt(encrypted_key), 16)

    return aes_key