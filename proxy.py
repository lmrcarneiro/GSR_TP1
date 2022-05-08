from pysnmp.hlapi import *
from snmppacket import *
from udpcommunication import *
from mibsecrow import *
from Crypto.Random.random import randint
from typing import List # para ter type hints

msg_id = 1
comm_string = "gsr2020"

def pysnmp_handle_errors(iterator, mib_object):
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication or errorStatus:
            return "Error fetching " + mib_object
    except Exception:
        return "Object " + mib_object + " does not exist!"
    
    if errorIndication or errorStatus:
        return "Error fetching " + mib_object
    else:
        response = ""
        for varBind in varBinds:
            response += ' = '.join([x.prettyPrint() for x in varBind])
        return response

def get_request_scalar(mib_object: str) -> str:
    # 2) pedir a MIB o objeto...
    iterator = getCmd(
        SnmpEngine(),
        CommunityData('gr2020', mpModel=0),
        UdpTransportTarget(('127.0.0.1', 161)),
        ContextData(),
        ObjectType(ObjectIdentity(mib_object))
    )
    return pysnmp_handle_errors(iterator, mib_object)

def get_next_request_scalar(mib_object: str) -> str:
    # 2) pedir a MIB o objeto...
    iterator = nextCmd(
        SnmpEngine(),
        CommunityData('gr2020', mpModel=0),
        UdpTransportTarget(('127.0.0.1', 161)),
        ContextData(),
        ObjectType(ObjectIdentity(mib_object))
    )
    return pysnmp_handle_errors(iterator, mib_object)

def mib_response_to_snmp_packet(snmp_request: SNMPPacket, mib_response: str) -> SNMPPacket:
    return SNMPPacket(
        msg_id = snmp_request.msg_id + 1,
        comm_string = snmp_request.comm_string,
        pdu_type = PDUType.RESPONSE,
        pdu =  mib_response,
        secret_key = None
    )

def store_req_in_mibsec(req: SNMPPacket):
    minId = pow(10, MIBsecRow.idOperDigits)
    maxId = pow(10, MIBsecRow.idOperDigits+1) -1

    mibsec_table.append(
        MIBsecRow(
            idOper=randint(minId, maxId),
            typeOper=req.pdu_type,
            idSource="aa",
            idDest="bb",
            oidArg="",
            valueArg="",
            typeArg=0,
            sizeArg=0,
            ttlOper=MIBsecRow.defaultTtl,
            statusOper=0
        )
    )

def store_resp_in_mibsec(resp: SNMPPacket):
    print("TODO store_resp_in_mibsec")

def handle_req(req: SNMPPacket) -> bytes:
    """ Recebe um pacote SNMP e devolve a string de resposta """

    # guardar na MIBsec o pedido efetuado caso o pedido seja válido
    # e consultar o agente consoante o pedido...
    if req.pdu_type == PDUType.GET_NEXT_REQUEST:
        store_req_in_mibsec(req)
        mib_response = get_next_request_scalar(req.pdu)
    elif req.pdu_type == PDUType.GET_REQUEST:
        store_req_in_mibsec(req)
        mib_response = get_request_scalar(req.pdu)
    else:
        mib_response = "Erro: O tipo de pedido é inválido..."

    # guardar resposta na mib
    store_resp_in_mibsec(mib_response)

    # mib_response (str) para snmp packet (SNMPPacket)
    snmp_packet_response = mib_response_to_snmp_packet(req, mib_response)
    return snmp_packet_response.convert_to_bytes()


# 0) definir objetos
#ObjectType(ObjectIdentity('netSnmp.11', 'secSecretKeyValue'), 2078136525)


listen_port = 5006
recv_buff_size = 1024

# instanciar MIBsec
mibsec_table: List[MIBsecRow] = list()

recv_packet = UDPCommunication.recv_UDP_block(listen_port, recv_buff_size)
while True:
    snmp_packet_bytes = next(recv_packet)
    snmp_packet_req = SNMPPacket.convert_to_packet(snmp_packet_bytes)
    response_bytes = handle_req(snmp_packet_req)
    
    UDPCommunication.send_UDP(response_bytes, 5005)