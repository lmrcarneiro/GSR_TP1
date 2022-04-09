from __future__ import annotations
import pickle
from cryptography import *
from enum import Enum

class PDUType(Enum):
	GET_REQUEST = 1
	GET_NEXT_REQUEST = 2
	RESPONSE = 3

class SNMPPacket:
	def __init__(self, msg_id, comm_string, pdu_type: PDUType, pdu, secret_key):
		self.msg_id: int = msg_id
		self.comm_string: str = comm_string
		self.pdu_type: PDUType = pdu_type
		self.pdu: str = pdu
		if secret_key is not None:
			self.cipher: bytes|None = self.get_pdu_cipher(secret_key)
		else:
			self.cipher: bytes|None = None

	def get_pdu_cipher(self, secret_key) -> bytes:
		mib_object_bytes = self.pdu.encode()
		hashed_obj = CryptoOperation.hash_msg(mib_object_bytes)
		return CryptoOperation.aes_encryption(hashed_obj, secret_key)

	def convert_to_bytes(self):
		return pickle.dumps(self)

	@staticmethod
	def convert_to_packet(snmp_packet_bytes) -> SNMPPacket:
		return pickle.loads(snmp_packet_bytes)

	def __str__(self):
		if self.cipher != None:
			return "Msg " + str(self.msg_id) + " \nCommunity String: " + self.comm_string + "\nPDU: " + self.pdu + "\nCipher: " + str(self.cipher)
		return "Msg " + str(self.msg_id) + " \nCommunity String: " + self.comm_string + "\nPDU: " + self.pdu