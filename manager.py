import socket
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import base64
import os

localhost = "127.0.0.1"

# de https://gist.github.com/syedrakib/d71c463fc61852b8d366

def encrypt_message(private_msg, encoded_secret_key, padding_character):
	# decode the encoded secret key
	secret_key = base64.b64decode(encoded_secret_key)
	# use the decoded secret key to create a AES cipher
	cipher = AES.new(secret_key)
	# pad the private_msg
	# because AES encryption requires the length of the msg to be a multiple of 16
	padded_private_msg = private_msg + (padding_character * ((16-len(private_msg)) % 16))
	# use the cipher to encrypt the padded message
	encrypted_msg = cipher.encrypt(padded_private_msg)
	# encode the encrypted msg for storing safely in the database
	encoded_encrypted_msg = base64.b64encode(encrypted_msg)
	# return encoded encrypted message
	return encoded_encrypted_msg

# POR TESTAR
def decrypt_message(encoded_encrypted_msg, encoded_secret_key, padding_character):
	# decode the encoded encrypted message and encoded secret key
	secret_key = base64.b64decode(encoded_secret_key)
	encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	# use the decoded secret key to create a AES cipher
	cipher = AES.new(secret_key)
	# use the cipher to decrypt the encrypted message
	decrypted_msg = cipher.decrypt(encrypted_msg)
	# unpad the encrypted message
	unpadded_private_msg = decrypted_msg.rstrip(padding_character)
	# return a decrypted original private message
	return unpadded_private_msg

def recv_UDP(port, buff_size):
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((localhost, port))
        data, addr = sock.recvfrom(buff_size)
        print(data.decode())

def send_UDP(msg_bytes, port):
    UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UDPClientSocket.sendto(msg_bytes, (localhost, port))

def hash_msg(msg_bytes):
    hash_object = SHA256.new(data=msg_bytes)
    return hash_object.digest()

listen_port = 5005
recv_buff_size = 1024
#listen_UDP = threading.Thread(target=rec_UDP, args=(listen_port, recv_buff_size))
#listen_UDP.start()

# 1) enviar sysDescr
send_to_port = 5006
mib_object = "sysDescr"

mib_object_bytes = mib_object.encode()
hashed_obj = hash_msg(mib_object_bytes)
# MAJOR SPAGHETTI ALERT
encoded_secret_key = base64.b64encode(os.urandom(16)) # TODO mudar
print(len(hashed_obj), len(encoded_secret_key))
ciphered_hashed_obj = encrypt_message(str(hashed_obj), encoded_secret_key, "{")

composed_msg = b"".join([mib_object_bytes, b" | ", ciphered_hashed_obj])
send_UDP(composed_msg, send_to_port)

# 4) obter resposta
recv_UDP(listen_port, recv_buff_size)