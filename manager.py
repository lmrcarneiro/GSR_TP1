from requeststable import RequestsTable, RequestsTableColumn
from snmppacket import *
from udpcommunication import *
from cryptography import *
from time import sleep
from sys import argv

COMM_STRING = "gsr2020"
SECRET_KEY = bytes("2661341895811798", "utf-8") # obtido da mib - tem de ter 128 bits = 16 bytes !!!
WAIT_TIME_BETWEEN_REQUESTS = 2
MAX_REQUESTS_TILL_TIMEOUT = 3

LISTEN_PORT = 5005
SEND_TO_PORT = 5006
RECV_BUFF_SIZE = 1024

#def send_request(msg_id, pdu_type, pdu, manager, agent, port):# to proxy
#	global SECRET_KEY
#	snmp_packet = SNMPPacket(msg_id, COMM_STRING, pdu_type, pdu, SECRET_KEY, manager, agent)
def send_request(snmp_packet: SNMPPacket, port):# to proxy
	snmp_packet_bytes = snmp_packet.convert_to_bytes()
	UDPCommunication.send_UDP(snmp_packet_bytes, port)

def send_req_recv_reply(req:str, my_manager_alias:str): # pdu_t:PDUType, pdu_s:str, manager:str, agent:str
	print("A fazer parse do pedido " + req)
	succ, request_type, real_oid, agent_alias = parse_request(req)
	if succ == False:
		print("Erro ao fazer parse do pedido " + req)
		return

	# Todos os pedidos vão ser do tipo SET
	#  para definir os 5 parâmetros
	#  (id operação, tipo, idSource, idDest e oidArg)
	generic_set_type = PacketType.SET_REQUEST

	# ID da operação é escolhido aleatoriamente no início
	# depois é sempre o mesmo
	operation_id_str = str(RequestsTable.get_random_operation_id())

	# OID para definir o tipo de operação é tipo TableReq.typeOp.145
	packet_oid = RequestsTable.name + "." + RequestsTableColumn.TYPE_OPER.value + "." + operation_id_str

	# ID dos pedidos vai ser aleatório entre pedidos
	packet_id = SNMPPacket.get_random_packet_id()

	# 1o pedido - definir o tipo de operação (145)
	snmp_packet = SNMPPacket(
		packet_id=packet_id,
		comm_str=COMM_STRING,
		packet_type=generic_set_type,
		oid=packet_oid,
		value=request_type,
		manager=my_manager_alias,
		agent=agent_alias,
		secret_key=SECRET_KEY
	)
	
	# Enviar pedidos continuos até obter resposta
	req_counter = 0
	snmp_packet_bytes = None
	while snmp_packet_bytes is None and req_counter<MAX_REQUESTS_TILL_TIMEOUT:
		req_counter+=1
		print("A enviar pedido " + str(snmp_packet))
		send_request(snmp_packet, SEND_TO_PORT)
		snmp_packet_bytes = UDPCommunication.recv_UDP_nonblock(LISTEN_PORT, RECV_BUFF_SIZE, WAIT_TIME_BETWEEN_REQUESTS)
	
	if snmp_packet_bytes is not None:
		response_snmp_packet = SNMPPacket.convert_to_packet(snmp_packet_bytes)
		decrypted_value_bytes = CryptoOperation.aes_decryption(
                response_snmp_packet.value, SECRET_KEY)
		if decrypted_value_bytes is None:
			print("Chave errada...")
		else:
			response = decrypted_value_bytes.decode()
			print("Proxy responded: " + SNMPPacket.proxy_response_to_message(response))
	else:
		print("Numero de pedidos excedido...")
	

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

def main():
	# Ler nome do manager da shell (se fornecido)
	n_args = len(argv)
	my_manager_alias = "Manager1"
	if n_args==2:
		my_manager_alias = str(argv[1])
		print("Nome do manager (lido da shell):" + my_manager_alias)

	# sysDescr
	sysDescr = ".1.3.6.1.2.1.1.1"

	req = "GET " + sysDescr + " Agent1"
	send_req_recv_reply(req, my_manager_alias)

if __name__ == "__main__":
	main()