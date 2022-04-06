import socket
from pysnmp.hlapi import *

localhost = "127.0.0.1"

def process_req(req):
    response = ""

    # 2) pedir a MIB o objeto...
    iterator = getCmd(
        SnmpEngine(),
        CommunityData('gr2020', mpModel=0),
        UdpTransportTarget(('127.0.0.1', 161)),
        ContextData(),
        #ObjectType(ObjectIdentity('SEC-MIB', 'sysDescr', 0))
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        return errorIndication
    elif errorStatus:
        return ('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            response += ' = '.join([x.prettyPrint() for x in varBind])
        return response

def handle_request_from_manager(recv_port, buff_size, send_port):
    while True:
        req = recv_UDP(recv_port, buff_size)
        print("received request:", req)
        response = process_req(req)
        send_UDP(response, send_port)

def recv_UDP(port, buff_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((localhost, port))
    data, addr = sock.recvfrom(buff_size)
    # data = data.decode()

    composed_msg =  data.split(b" | ")
    # TODO check cifra e hash etc..
    mib_object_bytes = composed_msg[0]
    cipher_bytes = composed_msg[1]

    return mib_object_bytes.decode() # transformar de bytes para string

def send_UDP(msg, port):
    msg_bytes = str.encode(msg)

    UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UDPClientSocket.sendto(msg_bytes, (localhost, port))

# 0) definir objetos
#ObjectType(ObjectIdentity('netSnmp.11', 'secSecretKeyValue'), 2078136525)

listen_port = 5006
recv_buff_size = 1024
handle_request_from_manager(listen_port, recv_buff_size, 5005) # spaghetti

#listen_UDP = threading.Thread(target=rec_UDP, args=(listen_port, recv_buff_size))
#listen_UDP.start()