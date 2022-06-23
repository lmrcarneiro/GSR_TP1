from __future__ import annotations
from multiprocessing import managers
from multiprocessing.sharedctypes import Value
import pickle
from cryptography import *
from enum import Enum
from Crypto.Random.random import randint

class PacketType(Enum):
	GET_REQUEST = 1
	GET_NEXT_REQUEST = 2
	SET_REQUEST = 3
	RESPONSE = 4

class ResponseType(Enum):
	SUCCESS = 0
	INVALID_OID = 1
	ID_ALREADY_EXISTS = 2
	UNAUTHORIZED_OPERATION = 3
	INVALID_KEY = 4
	INVALID_TYPE = 5

class SNMPPacket:
	"""Cria um pacote SNMP"""
	
	# Para criar o id aleatório do pacote
	packet_id_digits = 4
	minId = 10 ** (packet_id_digits-1)
	maxId = (10 ** packet_id_digits) -1

	def __init__(self, packet_id:int, comm_str:str, packet_type:PacketType,
				oid:str, value:str, manager:str, agent:str, secret_key:str):
		self.packet_id:int = packet_id
		self.community_string:str = comm_str
		self.packet_type:PacketType = packet_type
		self.object_identifier:str = oid
		self.value:bytes = self.cipher_value(value, secret_key)
		# como o alias do manager e do agent é sempre trocada,
		# vão ser criados novos campos
		self.manager:str = manager
		self.agent:str = agent
	
	def cipher_value(self, value:PacketType|ResponseType|str, secret_key) -> bytes:
		print(type(value))
		if type(value) == PacketType or type(value) == ResponseType:
			mib_object_bytes:bytes = str(value.value).encode()
		else:
			mib_object_bytes:bytes = value.encode()
		# hashed_obj = CryptoOperation.hash_msg(mib_object_bytes)
		return CryptoOperation.aes_encryption(mib_object_bytes, secret_key)

	def convert_to_bytes(self):
		return pickle.dumps(self)

	@staticmethod
	def convert_to_packet(snmp_packet_bytes) -> SNMPPacket:
		return pickle.loads(snmp_packet_bytes)

	"""Dada uma resposta do proxy ao pedido do manager (0,1,2,...),
	devolve a mensagem correta para mais fácil interpretação"""
	@staticmethod
	def proxy_response_to_message(response_type:str):
		msg = "Resposta nao prevista!"
		response_type:int = int(response_type)
		if(response_type == ResponseType.SUCCESS.value):
			msg = "A operacao ocorreu com sucesso!"
		return msg

	@classmethod
	def get_random_packet_id(cls):
		return randint(cls.minId, cls.maxId)

	def __str__(self):
		s = str(self.packet_id) + " [" + str(self.packet_type) + "]"
		# object identifier pode ser None quando o proxy responde
		# (só responde SUCCESS ou um erro)
		if self.object_identifier is not None:
			s += " (" + self.object_identifier + ")"
		return s