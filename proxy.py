from queue import Queue
from pysnmp.hlapi import *
from requeststable import RequestsTable, RequestsTableColumn, RequestsTableEntry
from snmppacket import *
from udpcommunication import *
from typing import List # para ter type hints
from threading import Thread

COMM_STRING = "gsr2020"
SECRET_KEY = bytes("2661341895811798", "utf-8") # obtido da mib - tem de ter 128 bits = 16 bytes !!!

LISTEN_PORT = 5006
SEND_TO_PORT = 5005
RECV_BUFF_SIZE = 1024

global_manager_requests_queue = Queue() # guarda os pedidos dos managers
global_requests_table:List[RequestsTableEntry] = list() # instanciar tabela de pedidos

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

def get_request_scalar(mib_object:str) -> str:
    # 2) pedir a MIB o objeto...
    iterator = getCmd(
        SnmpEngine(),
        CommunityData('gr2020', mpModel=0),
        UdpTransportTarget(('127.0.0.1', 161)),
        ContextData(),
        ObjectType(ObjectIdentity(mib_object))
    )
    return pysnmp_handle_errors(iterator, mib_object)

def get_next_request_scalar(mib_object:str) -> str:
    # 2) pedir a MIB o objeto...
    iterator = nextCmd(
        SnmpEngine(),
        CommunityData('gr2020', mpModel=0),
        UdpTransportTarget(('127.0.0.1', 161)),
        ContextData(),
        ObjectType(ObjectIdentity(mib_object))
    )
    return pysnmp_handle_errors(iterator, mib_object)

"""Vê se objeto com determinado id existe
na tabela de pedidos"""
def get_row_index_by_id(id:int):
    i=0
    len_table = len(global_requests_table)
    while i<len_table:
        line = global_requests_table[i]
        if line.idOper == id:
            return i
        i+=1
    return None

"""A partir de um oid do género TableReq.typeOp.145
retira o id (145) e a columa (typeOp) se o pedido
estiver bem formatado; se não estiver, retorna None"""
def get_table_id_and_column_from_oid(oid:str):
    valid_columns = [e.value for e in RequestsTableColumn]
    splitted_oid = oid.split(".")

    if len(splitted_oid) == 3:
        if splitted_oid[0] == RequestsTable.name:
            if splitted_oid[1] in valid_columns:
                return int(splitted_oid[2]),splitted_oid[1]
    return None,None

"""Guarda um pedido na tablela, por exemplo, para definir
o tipo de operação para GET no ID 145.
É garantido que o id fornecido ainda não existe na tabela
PARA JÁ"""
def save_request_in_table(table_id:int, table_column:str, decrypted_value:str,
                        manager_alias:str, agent_alias:str):
    
    row_index = get_row_index_by_id(table_id)
    
    new_entry = RequestsTableEntry(idOper=table_id)
    new_entry.set_column(table_column, decrypted_value)

    if row_index is None:
        # nenhum objeto existe nesse ID, pelo que podemos começar a guardar
        # o que o manager quiser (+ ID + manager + agente)
        new_entry.set_column(RequestsTableColumn.ID_OPER.value, table_id)
        new_entry.set_column(RequestsTableColumn.ID_SOURCE.value, manager_alias)
        new_entry.set_column(RequestsTableColumn.ID_DEST.value, agent_alias)
        global_requests_table.append(new_entry)
        return ResponseType.SUCCESS
    else:
        # linha já existe, ou seja, temos que ver se 
        # este manager é o autorizado
        # o agente está correto
        row:RequestsTableEntry = global_requests_table[row_index]
        if row.idSource==manager_alias and row.idDest==agent_alias:
            global_requests_table.append(new_entry)
            print("a imprimir linha: " + row)
            return ResponseType.SUCCESS
        else:
            print("Manager nao esta autorizado a fazer essa operacao...")
            return ResponseType.UNAUTHORIZED_OPERATION

def handle_manager_request(request:SNMPPacket) -> bytes:
    """ Recebe um pacote SNMP e devolve a resposta
        (Pacote SNMP para bytes) """

    respond_flag = True # por norma, é para responder
    # exceto quando a chave de decifra está inválida

    if request.packet_type == PacketType.SET_REQUEST:
        packet_oid = request.object_identifier

        table_id,table_column = get_table_id_and_column_from_oid(packet_oid)
        if table_id is None:
            # oid mal formatado...
            print("Erro de formatacao no oid " + packet_oid)
            response = ResponseType.INVALID_OID
        else:
            # ver se o value fornecido no pedido é válido
            # (tentar decifrá-lo)
            decrypted_value_bytes = CryptoOperation.aes_decryption(
                request.value, SECRET_KEY)
            if decrypted_value_bytes is None:
                # Nao vai responder por questoes de segurança...
                # Se for um atacante, a informaçao que a chave é inválida
                # pode ser benéfica
                respond_flag = False
                print("Chave inválida...")
            else:
                decrypted_value = decrypted_value_bytes.decode()
                #print("Valor do pedido: " + decrypted_value)

                response = save_request_in_table(table_id, table_column, decrypted_value, 
                request.manager, request.agent)
    else:
        print("Request " + str(request) + " ainda nao previsto...")
        print("Tratar de outros tipos de request!!!")
        response = ResponseType.INVALID_TYPE

    if respond_flag:
        response_snmp_packet = SNMPPacket(
            packet_id=request.packet_id,
            comm_str=COMM_STRING,
            packet_type=PacketType.RESPONSE,
            oid=None,
            value=response,
            manager=request.manager,
            agent=request.agent,
            secret_key=SECRET_KEY
        )
        response_bytes = response_snmp_packet.convert_to_bytes()
        UDPCommunication.send_UDP(response_bytes, SEND_TO_PORT)

    '''snmp_packet_response = mib_response_to_snmp_packet(mib_response)
    return snmp_packet_response.convert_to_bytes()
    '''


# 0) definir objetos
#ObjectType(ObjectIdentity('netSnmp.11', 'secSecretKeyValue'), 2078136525)

def handle_requests():
    print("Thread que trata dos pedidos instanciada!")

    while True:
        manager_request = SNMPPacket.convert_to_packet(
            global_manager_requests_queue.get()
        )
        print("Pedido do manager: " + str(manager_request))

        handle_manager_request(manager_request)

def main():
    # começar thread que trata dos pedidos
    t = Thread(target=handle_requests)
    t.start()

    # Thread principal apenas coloca o que recebe numa Queue para a 
    # outra thread tratar
    recv_packet = UDPCommunication.recv_UDP_block(LISTEN_PORT, RECV_BUFF_SIZE)
    while True:
        global_manager_requests_queue.put(
            next(recv_packet)
        )

if __name__ == "__main__":
	main()