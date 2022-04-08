# from pysnmp.hlapi import *
from snmppacket import *
from udpcommunication import *

msg_id = 1
comm_string = "gsr2020"

'''
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
'''


# 0) definir objetos
#ObjectType(ObjectIdentity('netSnmp.11', 'secSecretKeyValue'), 2078136525)


listen_port = 5006
recv_buff_size = 1024

recv_packet = UDPCommunication.recv_UDP_block(listen_port, recv_buff_size)
while True:
    snmp_packet_bytes = next(recv_packet)
    snmp_packet_req = SNMPPacket.convert_to_packet(snmp_packet_bytes)
    response_pdu = "TODOOO"
    
    response_packet = SNMPPacket(
        snmp_packet_req.msg_id + 1,
        snmp_packet_req.comm_string,
        response_pdu,
        None
    )
    response_bytes = response_packet.convert_to_bytes()
    UDPCommunication.send_UDP(response_bytes, 5005)