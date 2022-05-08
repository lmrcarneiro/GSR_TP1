from snmppacket import *
from udpcommunication import *
from cryptography import *

msg_id = 1
comm_string = "gsr2020"
secret_key = 2661341895811798 # obtido da mib - tem de ter 128 bits = 16 bytes !!!

def send_request(pdu_type, pdu, port): # to proxy
	global msg_id
	global secret_key
	snmp_packet = SNMPPacket(msg_id, comm_string, pdu_type, pdu, secret_key)
	snmp_packet_bytes = snmp_packet.convert_to_bytes()
	UDPCommunication.send_UDP(snmp_packet_bytes, port)
	msg_id += 1

listen_port = 5005
send_to_port = 5006
recv_buff_size = 1024

def send_req_recv_reply(pdu_t: PDUType, pdu_s: str):
	send_request(pdu_t, pdu_s, send_to_port)

	# 4) obter resposta
	snmp_packet_bytes = UDPCommunication.recv_UDP(listen_port, recv_buff_size)
	print(SNMPPacket.convert_to_packet(snmp_packet_bytes).pdu)

# sysDescr
pdu_s = ".1.3.6.1.2.1.1.1"

# GET NEXT REQUEST
pdu_t = PDUType.GET_NEXT_REQUEST
send_req_recv_reply(pdu_t, pdu_s)

# GET REQUEST
pdu_t = PDUType.GET_REQUEST
pdu_s += ".0"
send_req_recv_reply(pdu_t, pdu_s)