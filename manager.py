import socket, pickle
from snmppacket import *
from udpcommunication import *
from cryptography import *
from Crypto.Random import get_random_bytes

msg_id = 1
comm_string = "gsr2020"
secret_key = get_random_bytes(16) # obter da mib - tem de ter 128 bits = 16 bytes !!!

def send_request(pdu, port): # to proxy
	global msg_id
	global secret_key
	snmp_packet = SNMPPacket(msg_id, comm_string, pdu, secret_key)
	snmp_packet_bytes = snmp_packet.convert_to_bytes()
	UDPCommunication.send_UDP(snmp_packet_bytes, port)
	msg_id += 1

listen_port = 5005
send_to_port = 5006
recv_buff_size = 1024

# 1) enviar sysDescr
mib_object = "sysDescr"
send_request(mib_object, send_to_port)

# 4) obter resposta
snmp_packet_bytes = UDPCommunication.recv_UDP(listen_port, recv_buff_size)
print(SNMPPacket.convert_to_packet(snmp_packet_bytes))