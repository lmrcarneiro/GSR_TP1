import pickle
from cryptography import *

class SNMPPacket:
	def __init__(self, msg_id, comm_string, pdu, secret_key):
		self.msg_id = msg_id
		self.comm_string = comm_string
		self.pdu = pdu
		if secret_key is not None:
			self.cipher = self.get_pdu_cipher(pdu, secret_key)
		else:
			self.cipher = None

	def get_pdu_cipher(self, pdu, secret_key):
		mib_object_bytes = pdu.encode()
		hashed_obj = CryptoOperation.hash_msg(mib_object_bytes)
		return CryptoOperation.aes_encryption(hashed_obj, secret_key)

	def convert_to_bytes(self):
		return pickle.dumps(self)

	@staticmethod
	def convert_to_packet(snmp_packet_bytes):
		return pickle.loads(snmp_packet_bytes)

	def __str__(self):
		if self.cipher != None:
			return "Msg " + str(self.msg_id) + " \nCommunity String: " + self.comm_string + "\nPDU: " + self.pdu + "\nCipher: " + self.cipher.decode()
		return "Msg " + str(self.msg_id) + " \nCommunity String: " + self.comm_string + "\nPDU: " + self.pdu