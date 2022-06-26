from ctypes import Union
from typing import List
from requeststable import RequestsTable, RequestsTableColumn
from snmppacket import *
from udpcommunication import *
from cryptography import *
from time import sleep
from sys import argv
from configparser import ConfigParser

DEBUG_FLAG = 0

COMM_STRING = "gsr2020"
KEY_STORAGE_FILENAME = "KEY_CONFIG.txt"
KEY_FILE_SECTION = "manager"
SECRET_KEY = None

WAIT_TIME_BETWEEN_REQUESTS = 2
MAX_REQUESTS_TILL_TIMEOUT = 3
SET_TO_GET_DELAY = 0.1

LISTEN_PORT = 5005
SEND_TO_PORT = 5006
RECV_BUFF_SIZE = 1024

def send_request(snmp_packet: SNMPPacket, port):# to proxy
	snmp_packet_bytes = snmp_packet.convert_to_bytes()
	UDPCommunication.send_UDP(snmp_packet_bytes, port)

"""Envia um pedido MAX_REQUESTS_TILL_TIMEOUT vezes
Retorna um inteiro a indicar o tipo de resposta 
(tipo ProxyResponseType) e o valor"""
def send_requests_till_answer(snmp_packet_to_send:SNMPPacket):
	req_counter = 0
	snmp_packet_bytes = None
	while snmp_packet_bytes is None and req_counter<MAX_REQUESTS_TILL_TIMEOUT:
		req_counter+=1
		if DEBUG_FLAG==1:
			print("A enviar pedido " + str(snmp_packet_to_send))
		send_request(snmp_packet_to_send, SEND_TO_PORT)
		snmp_packet_bytes = UDPCommunication.recv_UDP_nonblock(LISTEN_PORT, RECV_BUFF_SIZE, WAIT_TIME_BETWEEN_REQUESTS)
		
	if snmp_packet_bytes is not None:
		response_snmp_packet = SNMPPacket.convert_to_packet(snmp_packet_bytes)
		
		# decifrar o status da resposta
		decrypted_status_bytes = CryptoOperation.aes_decryption(
                response_snmp_packet.response_status, SECRET_KEY)
		if decrypted_status_bytes is None:
			print("Chave errada...")
			return None,None
		status = int(decrypted_status_bytes.decode())

		# decifrar também o valor se o pacote a enviar for do tipo get ou getnext (e se for bem sucedido)
		# ou entao se o ID do pacote recebido for invalido, pois o novo ID que o proxy sugere está no valor
		c_get = snmp_packet_to_send.packet_type == PacketType.GET_REQUEST
		c_getn = snmp_packet_to_send.packet_type == PacketType.GET_NEXT_REQUEST
		c_succ = status == ResponseStatus.SUCCESS.value
		c_set = snmp_packet_to_send.packet_type == PacketType.SET_REQUEST	
		c_id = status == ResponseStatus.ID_ALREADY_EXISTS.value 
		
		# se buscarmos um valor com sucesso ou se dermos set com um id invalido
		if  ((c_get or c_getn) and c_succ) or (c_set and c_id):
			decrypted_value_bytes = CryptoOperation.aes_decryption(
					response_snmp_packet.value, SECRET_KEY)
			value = decrypted_value_bytes.decode()
			return status,value		
		return status,None

	print("Numero de pedidos excedido...")
	return None,None

def create_packet_to_send(packet_type, packet_oid, value, manager, agent):
	# ID dos pedidos vai ser aleatório entre pedidos
	packet_id = SNMPPacket.get_random_packet_id()

	# 1o pedido - definir o tipo de operação (145)
	# juntamente com id, origem e destino
	snmp_packet = SNMPPacket(
		packet_id=packet_id,
		comm_str=COMM_STRING,
		packet_type=packet_type,
		oid=packet_oid,
		value=value,
		manager=manager,
		agent=agent,
		secret_key=SECRET_KEY
	)
	return snmp_packet

def send_req_recv_reply(req:str, my_manager_alias:str, received_operation_id:str=None): # pdu_t:PDUType, pdu_s:str, manager:str, agent:str
	if DEBUG_FLAG==1:
		print("A fazer parse do pedido " + req)
	succ, request_type, real_oid, agent_alias = parse_request(req)
	if succ == False:
		print("Erro ao fazer parse do pedido " + req)
		return

	# Os pedidos para definir os 5 parâmetros
	# (id operação, tipo, idSource, idDest e oidArg)
	# vão ser do tipo SET
	generic_set_type = PacketType.SET_REQUEST

	# ID da operação é escolhido aleatoriamente no início
	# depois é sempre o mesmo
	# (se o ID for None, estamos a realizar esta operacao pela primeira vez
	# caso contrário, já obtivemos ID inválido na chamada passada)
	if received_operation_id is None:
		operation_id_str = str(RequestsTable.get_random_operation_id())
	else:
		operation_id_str = received_operation_id

	# OID para definir o tipo de operação é tipo TableReq.typeOp.145
	packet_oid = RequestsTable.name + "." + RequestsTableColumn.TYPE_OPER.value + "." + operation_id_str
	
	packet_to_send = create_packet_to_send(
		packet_type=generic_set_type,
		packet_oid=packet_oid,
		value=request_type,
		manager=my_manager_alias,
		agent=agent_alias
	)
	
	status = ResponseStatus.ID_ALREADY_EXISTS.value
	while status == ResponseStatus.ID_ALREADY_EXISTS.value:
		# Enviar pedidos continuos até obter resposta
		status,value = send_requests_till_answer(packet_to_send)
		#response = SNMPPacket.proxy_response_to_message(code_response)
		#print("Proxy respondeu: " + response)
		
		#  SUCCESS INVALID_OID INVALID_TYPE ID_ALREADY_EXISTS
		if status is None: # Nº pedidos excedido
			return
		if status != ResponseStatus.SUCCESS.value:
			# Se ID já existir, temos de ler o sugerido e tentar outra vez...
			if status == ResponseStatus.ID_ALREADY_EXISTS.value:
				if received_operation_id is None:
					if DEBUG_FLAG==1:
						print("ID inválido, a tentar outra vez!")
					send_req_recv_reply(req, my_manager_alias, value)
			else:
				print(SNMPPacket.response_status_to_message(status))
			return

	# 2o pedido - definir o oid de operação (145)

	# OID para definir o tipo de operação é tipo TableReq.typeOp.145
	packet_oid = RequestsTable.name + "." + RequestsTableColumn.OID_ARG.value + "." + operation_id_str
	
	packet_to_send = create_packet_to_send(
		packet_type=generic_set_type,
		packet_oid=packet_oid,
		value=real_oid,
		manager=my_manager_alias,
		agent=agent_alias
	)
	
	# Enviar pedidos continuos até obter resposta
	status,_ = send_requests_till_answer(packet_to_send)
	#response = SNMPPacket.proxy_response_to_message(code_response)
	#print("Proxy respondeu: " + response)
	# SAME_OID_ALREADY_EXISTS DIFFERENT UNAUTHORIZED
	if status is None: # Nº pedidos excedido
		return
	if status!=ResponseStatus.SUCCESS.value and status!=ResponseStatus.SAME_OID_ALREADY_EXISTS.value:
		if status == ResponseStatus.DIFFERENT_OID_ALREADY_EXISTS.value or status == ResponseStatus.UNAUTHORIZED_OPERATION.value:
			print("Erro de concorrência ao definir valores na tabela...")
		return
	
	# dar algum tempo ao proxy de definir o valor na tabela...
	sleep(SET_TO_GET_DELAY)
	
	packet_oid = RequestsTable.name + "." + RequestsTableColumn.VALUE_ARG.value + "." + operation_id_str

	packet_to_send = create_packet_to_send(
		packet_type=request_type,
		packet_oid=packet_oid,
		value=None,
		manager=my_manager_alias,
		agent=agent_alias
	)
	status,value = send_requests_till_answer(packet_to_send)
	if status is None: # Nº pedidos excedido
		return
	if status != ResponseStatus.SUCCESS.value:
		print(SNMPPacket.response_status_to_message(status))
	else:
		print(value)
	

"""Recebe a string do manager a enviar e separa
o tipo de pedido, o OID, manager e agente"""
def parse_request(req:str):
	# Retorna False no primeiro argumento para indicar
	# que houve um erro ao fazer parse do pedido
	error_ret = False, None, None, None

	split_req = req.split(" ")
	if len(split_req)!=3:
		print("Numero de argumentos incorretos")
		return error_ret

	# tipo pedido
	if split_req[0] == "GET":
		req_type = PacketType.GET_REQUEST
	elif split_req[0] == "GETNEXT":
		req_type = PacketType.GET_NEXT_REQUEST
	else:
		print("Tipo de pedido incorreto")
		return error_ret

	# OID
	oid = split_req[1]
	
	# agente
	agent_alias = split_req[2]

	return True, req_type, oid, agent_alias

def main(my_manager_alias):
	# sysDescr
	sysDescr = ".1.3.6.1.2.1.1.1"

	req = "GETNEXT " + sysDescr + " Agent1"
	send_req_recv_reply(req, my_manager_alias)

	# ERRO
	req = "GET " + sysDescr + " Agent1"
	send_req_recv_reply(req, my_manager_alias)

	# ERRO
	req = "GETNEXT " + "sysDescr" + " Agent1"
	send_req_recv_reply(req, my_manager_alias)

if __name__ == "__main__":
	# operacoes config
	# Ler nome do manager da shell (se fornecido)
	n_args = len(argv)
	my_manager_alias = "manager1"
	if n_args==2:
		my_manager_alias = str(argv[1])
		print("Nome do manager (lido da shell):" + my_manager_alias)

	# Ler chave privada para comunicar com proxy
	parser = ConfigParser()
	parser.read(KEY_STORAGE_FILENAME)
	
	try:
		key = parser.get(KEY_FILE_SECTION, my_manager_alias)
		SECRET_KEY = bytes(key,"utf-8")
	except Exception:
		print("Erro: chave não definida para o manager " + my_manager_alias)
		exit(-1)

	main(my_manager_alias)