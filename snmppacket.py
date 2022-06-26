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

class ResponseStatus(Enum):
	# Respostas comuns
	SUCCESS = 0
	# A fazer SET
	INVALID_TABLE_OID = 1
	INVALID_TYPE = 2
	# Ao definir id, tipo, manager e agent
	ID_ALREADY_EXISTS = 3
	# Ao definir o OID
	SAME_OID_ALREADY_EXISTS = 4
	DIFFERENT_OID_ALREADY_EXISTS = 5
	UNAUTHORIZED_OPERATION = 6
	# ao fazer GET
	FETCH_ERROR = 7


class SNMPPacket:
	"""Cria um pacote SNMP"""
	
	# Para criar o id aleatório do pacote
	packet_id_digits = 4
	minId = 10 ** (packet_id_digits-1)
	maxId = (10 ** packet_id_digits) -1

	def __init__(self, packet_id:int, comm_str:str, packet_type:PacketType,
				oid:str, value:str, manager:str, agent:str, secret_key:str, 
				response_status:ResponseStatus=None):
		self.packet_id:int = packet_id
		self.community_string:str = comm_str
		self.packet_type:PacketType = packet_type
		self.object_identifier:str = oid
		self.value:bytes = self.cipher_value(value, secret_key)
		# como o alias do manager e do agent é sempre trocada,
		# vão ser criados novos campos
		self.manager:str = manager
		self.agent:str = agent
		# campo para indicar o status de resposta (tipo de erro ou sucesso)
		# esta vai também ser cifrada
		self.response_status:bytes = self.cipher_response_status(response_status, secret_key)

	def cipher_value(self, value:PacketType|str, secret_key) -> bytes:
		if value is None: # ao fazer GET
			return None
		if type(value) == PacketType:
			mib_object_bytes:bytes = str(value.value).encode()
		else:
			mib_object_bytes:bytes = value.encode()
		# hashed_obj = CryptoOperation.hash_msg(mib_object_bytes)
		return CryptoOperation.aes_encryption(mib_object_bytes, secret_key)

	def cipher_response_status(self, status:ResponseStatus, secret_key) -> bytes:
		if status is None:
			return None
		status_bytes:bytes = str(status.value).encode()
		return CryptoOperation.aes_encryption(status_bytes, secret_key)

	def convert_to_bytes(self):
		return pickle.dumps(self)

	@staticmethod
	def convert_to_packet(snmp_packet_bytes) -> SNMPPacket:
		return pickle.loads(snmp_packet_bytes)

	"""Dada uma resposta do proxy ao pedido do manager (0,1,2,...),
	devolve a mensagem correta para mais fácil interpretação"""
	@staticmethod
	def response_status_to_message(int_response_type:int):
		msg = "Resposta " + str(int_response_type) + " nao prevista na funcao!"
		if int_response_type == ResponseStatus.SUCCESS.value:
			msg = "A operacao ocorreu com sucesso!"
		elif int_response_type == ResponseStatus.INVALID_TABLE_OID.value:
			msg = "OID mal formatado"
		elif int_response_type == ResponseStatus.INVALID_TYPE.value:
			msg = "Tipo de pedido invalido"
		elif int_response_type == ResponseStatus.ID_ALREADY_EXISTS.value:
			msg = "ID fornecido ja existe na tabela"
		elif int_response_type == ResponseStatus.SAME_OID_ALREADY_EXISTS.value:
			msg = "O mesmo OID ja esta definido nesse objeto da tabela"
		elif int_response_type == ResponseStatus.DIFFERENT_OID_ALREADY_EXISTS.value:
			msg = "Um OID diferente ja esta definido nesse objeto da tabela"
		elif int_response_type == ResponseStatus.UNAUTHORIZED_OPERATION.value:
			msg = "Operacao nao autorizada"
		return msg

	"""Se houver algum erro a guardar n"""

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