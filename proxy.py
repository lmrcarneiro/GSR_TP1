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

def mib_response_to_snmp_packet(mib_response: MIBsecRow) -> SNMPPacket:
    msg_id=mib_response.idOper
    comm_string=comm_string
    pdu_type=PDUType.RESPONSE
    secret_key=None, # TODO é preciso mudar isto?
    if mib_response is None: # nao foi encontrado na mib
        pdu="Erro: Objeto não encontrado..."
        manager=None
        agent=None
    else:
        pdu=mib_response.oidArg
        manager=mib_response.idSource
        agent=mib_response.idDest

    return SNMPPacket(
        msg_id=mib_response.idOper,
        comm_string=comm_string,
        pdu_type=PDUType.RESPONSE,
        pdu=mib_response.oidArg,
        secret_key=None, # TODO é preciso mudar isto?
        manager=mib_response.idSource,
        agent=mib_response.idDest
    )

def store_req_in_mibsec(req: SNMPPacket):
    minId = pow(10, MIBsecRow.idOperDigits)
    maxId = pow(10, MIBsecRow.idOperDigits+1) -1

    mibsec_table.append(
        MIBsecRow(
            idOper=randint(minId, maxId),
            typeOper=req.pdu_type,
            idSource=req.manager, #todo
            idDest=req.agent, # todo
            oidArg=req.pdu,
            valueArg="",
            typeArg=0,
            sizeArg=0,
            ttlOper=MIBsecRow.defaultTtl,
            statusOper=0
        )
    )

def store_resp_in_mibsec(resp: SNMPPacket):
    print("TODO store_resp_in_mibsec")

"""Para além do objeto, retorna 0 se o objeto nao
for encontrado ou 1 se for encontrado, mas ainda
não tiver valor """
def get_resp_from_mibsec(req: SNMPPacket):
    not_found_ret = 0, None
    found_no_obj = 1, None
    print("TODO buscar resposta da mibsec")
    return not_found_ret

def handle_req(req: SNMPPacket) -> bytes:
    """ Recebe um pacote SNMP e devolve a string de resposta """

    # guardar na MIBsec o pedido efetuado caso o pedido seja válido
    # e consultar o agente consoante o pedido...
    if req.msg_id == 1:
        if req.pdu_type == PDUType.GET_NEXT_REQUEST:
            store_req_in_mibsec(req)
            mib_response = get_next_request_scalar(req.pdu)
            store_resp_in_mibsec(mib_response)
        elif req.pdu_type == PDUType.GET_REQUEST:
            store_req_in_mibsec(req)
            mib_response = get_request_scalar(req.pdu)
            store_resp_in_mibsec(mib_response)
        else:
            mib_response = "Erro: O tipo de pedido é inválido..."
    else: # buscar à MIB (assumindo que o pedido anterior chegou ao agente..)
          # TODO no futuro não assumir isto
        mib_response = get_resp_from_mibsec(req)
        if mib_response is None: # TODO ver se o proxy responde ou não...
            mib_response = "Objeto nao encontrado na MIB.."
            print(mib_response)
        snmp_packet_response = mib_response_to_snmp_packet(mib_response)
        return snmp_packet_response.convert_to_bytes()
    

    # mib_response (str) para snmp packet (SNMPPacket)
    #


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
    
    handle_req(snmp_packet_req)
    #response_bytes = handle_req(snmp_packet_req)
    #UDPCommunication.send_UDP(response_bytes, 5005)