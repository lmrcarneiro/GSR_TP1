from pysnmp.hlapi import *
from snmppacket import *
from udpcommunication import *

msg_id = 1
comm_string = "gsr2020"

def translate_req(req: SNMPPacket) -> SNMPPacket:
    return req

def get_request_scalar(mib_object: str, pos: int) -> str:
    print("REQUESTING " + mib_object)

    # 2) pedir a MIB o objeto...
    iterator = getCmd(
        SnmpEngine(),
        CommunityData('gr2020', mpModel=0),
        UdpTransportTarget(('127.0.0.1', 161)),
        ContextData(),
        ObjectType(ObjectIdentity('SNMPv2-MIB', mib_object, pos))
    )

    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication or errorStatus:
            return "Error fetching " + mib_object
    except Exception:
        return "Object " + mib_object + " does not exist!"
    """
    if errorIndication:
        return errorIndication
    elif errorStatus:
        return ('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    """
    if errorIndication or errorStatus:
        return "Error fetching " + mib_object
    else:
        response = ""
        for varBind in varBinds:
            response += ' = '.join([x.prettyPrint() for x in varBind])
        return response

def get_next_request_scalar(mib_object: str) -> str:
    return get_request_scalar(mib_object, 0)

def mib_response_to_snmp_packet(snmp_request: SNMPPacket, mib_response: str) -> SNMPPacket:
    return SNMPPacket(
        msg_id = snmp_request.msg_id + 1,
        comm_string = snmp_request.comm_string,
        pdu_type = PDUType.RESPONSE, # spaghetti
        pdu =  mib_response,
        secret_key = None
    )

def handle_req(snmp_packet_req: SNMPPacket) -> bytes:
    """ Recebe um pacote SNMP e devolve a string de resposta """

    # traduzir request ...
    translated_req = translate_req(snmp_packet_req)

    # ir a mib consoante o pedido...
    if translated_req.pdu_type == PDUType.GET_NEXT_REQUEST:
        mib_response = get_next_request_scalar(translated_req.pdu)
    elif translated_req.pdu_type == PDUType.GET_REQUEST:
        print("!!! ASSUMING POSITION 0 !!!")
        mib_response = get_request_scalar(translated_req.pdu, 0)
    else:
        mib_response = "Erro: O tipo de pedido é inválido..."

    # mib_response (str) para snmp packet (SNMPPacket)
    snmp_packet_response = mib_response_to_snmp_packet(translated_req, mib_response)
    return snmp_packet_response.convert_to_bytes()


# 0) definir objetos
#ObjectType(ObjectIdentity('netSnmp.11', 'secSecretKeyValue'), 2078136525)


listen_port = 5006
recv_buff_size = 1024

recv_packet = UDPCommunication.recv_UDP_block(listen_port, recv_buff_size)
while True:
    snmp_packet_bytes = next(recv_packet)
    snmp_packet_req = SNMPPacket.convert_to_packet(snmp_packet_bytes)
    response_bytes = handle_req(snmp_packet_req)
    
    UDPCommunication.send_UDP(response_bytes, 5005)