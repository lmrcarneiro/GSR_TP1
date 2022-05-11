from snmppacket import *
from udpcommunication import *
from cryptography import *
from time import sleep

comm_string = "gsr2020"
secret_key = bytes("2661341895811798", "utf-8") # obtido da mib - tem de ter 128 bits = 16 bytes !!!

def send_request(msg_id, pdu_type, pdu, manager, agent, port): # to proxy
	global secret_key
	snmp_packet = SNMPPacket(msg_id, comm_string, pdu_type, pdu, secret_key, manager, agent)
	snmp_packet_bytes = snmp_packet.convert_to_bytes()
	UDPCommunication.send_UDP(snmp_packet_bytes, port)
	msg_id += 1

listen_port = 5005
send_to_port = 5006
recv_buff_size = 1024

def send_req_recv_reply(pdu_t: PDUType, pdu_s: str, manager: str, agent: str):
	msg_id = 0

	# Envia o primeiro pedido
	msg_id += 1
	print("Request " + str(msg_id))
	send_request(msg_id, pdu_t, pdu_s, manager, agent, send_to_port)

	# Espera para dar tempo ao proxy de guardar o valor na tabela
	sleep(3)

	# Enviar pedidos continuos até obter resposta
	snmp_packet_bytes = None
	while snmp_packet_bytes is None:
		msg_id += 1
		print("Request " + str(msg_id))
		send_request(msg_id, pdu_t, pdu_s, manager, agent, send_to_port)
		snmp_packet_bytes = UDPCommunication.recv_UDP_nonblock(listen_port, recv_buff_size, 5)
	print(SNMPPacket.convert_to_packet(snmp_packet_bytes).pdu)

"""Recebe a string do manager a enviar e separa
o tipo de pedido, o OID, manager e agente"""
def parse_request(req: str):
	error_ret = False, None, None, None, None
	split_req = req.split(" ")
	if len(split_req) < 4:
		return error_ret
	# tipo pedido
	if split_req[0] == "get":
		req_type = PDUType.GET_REQUEST
	elif split_req[0] == "getnext":
		req_type = PDUType.GET_NEXT_REQUEST
	else:
		return error_ret
	# OID
	req_oid = split_req[1]
	# Manager
	req_manager = split_req[2]
	# agente
	req_agent = split_req[3]
	return True, req_type, req_oid, req_manager, req_agent

def main():
	# sysDescr
	pdu_s = ".1.3.6.1.2.1.1.1"

	# GET NEXT REQUEST
	req = "getnext " + pdu_s + " Man1 AgentX"
	succ, req_type, req_oid, req_manager, req_agent = parse_request(req)
	if succ == False:
		print("FATAL ERROR")
		exit(0)
	send_req_recv_reply(req_type, req_oid, req_manager, req_agent)

	# GET REQUEST
	req = "get " + pdu_s + ".0" + " Man1 AgentX"
	succ, req_type, req_oid, req_manager, req_agent = parse_request(req)
	if succ == False:
		print("FATAL ERROR")
		exit(0)
	send_req_recv_reply(req_type, req_oid, req_manager, req_agent)

if __name__ == "__main__":
	main()