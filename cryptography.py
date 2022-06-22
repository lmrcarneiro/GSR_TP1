from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding

class CryptoOperation:

    @staticmethod
    def aes_encryption(private_msg:bytes, secret_key):
        cipher = AES.new(secret_key, AES.MODE_ECB)
        padded_private_msg = Padding.pad(private_msg, 16)
        encrypted_msg = cipher.encrypt(padded_private_msg)
        return encrypted_msg

    # POR TESTAR
    @staticmethod
    def aes_decryption(encrypted_msg:bytes, secret_key):
        cipher = AES.new(secret_key, AES.MODE_ECB)
        decrypted_msg = cipher.decrypt(encrypted_msg)
        unpadded_private_msg = Padding.unpad(decrypted_msg, 16)
        return unpadded_private_msg

    @staticmethod
    def hash_msg(msg:bytes):
        hash_object = SHA256.new(data=msg)
        return hash_object.digest()

    