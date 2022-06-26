from queue import Queue
from time import sleep
from pysnmp.hlapi import *
from keystable import KeysTableEntry
from requeststable import RequestStatus, RequestsTable, RequestsTableColumn, RequestsTableEntry
from snmppacket import *
from udpcommunication import *
from typing import List # para ter type hints
from threading import Thread, Lock
from datetime import datetime, timedelta
from configparser import ConfigParser

COMM_STRING = "gsr2020"
KEY_STORAGE_FILENAME = "KEY_CONFIG.txt"
KEY_FILE_SECTION = "manager"

FILL_TABLE_DELAY = 0.1
CLEAN_TABLE_DELAY = 10
DELETE_NON_VALID_TABLE_ENTRY_DELAY = 120

LISTEN_PORT = 5006
SEND_TO_PORT = 5005
RECV_BUFF_SIZE = 1024

global_manager_requests_queue = Queue() # guarda os pedidos dos managers
global_requests_table:List[RequestsTableEntry] = list() # instanciar tabela de pedidos
global_requests_table_lock = Lock()
global_keys_table:List[KeysTableEntry] = list() # instanciar tabela de chaves
global_manager_blacklist = []

"""Retorna True,Valor objeto ou False,None"""
def pysnmp_handle_errors(iterator, mib_object):
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        
        if errorIndication:
            return ResponseStatus.FETCH_ERROR, errorIndication
        elif errorStatus:
            response = '%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?')
            return ResponseStatus.FETCH_ERROR, response
    except Exception:
        return ResponseStatus.FETCH_ERROR,"Unspecified error with OID " + mib_object
    
    response = ""
    for varBind in varBinds:
        response += ' = '.join([x.prettyPrint() for x in varBind])
    return ResponseStatus.SUCCESS, response

def get_request_scalar(mib_object:str):
    # 2) pedir a MIB o objeto...
    iterator = getCmd(
        SnmpEngine(),
        CommunityData('gr2020', mpModel=0),
        UdpTransportTarget(('127.0.0.1', 161)),
        ContextData(),
        ObjectType(ObjectIdentity(mib_object))
    )
    return pysnmp_handle_errors(iterator, mib_object)

def get_next_request_scalar(mib_object:str):
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
    with global_requests_table_lock:
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
o tipo de operação para GET no ID 145."""
def save_request_in_table(table_id:int, table_column:str, decrypted_value:str,
                        manager_alias:str, agent_alias:str):
    
    row_index = get_row_index_by_id(table_id)

    if row_index is None:
        # nenhum objeto existe nesse ID, pelo que podemos começar a guardar
        # o que o manager quiser (+ ID + manager + agente)
        new_entry = RequestsTableEntry(idOper=table_id)
        new_entry.set_column(table_column, decrypted_value)
        new_entry.set_column(RequestsTableColumn.ID_OPER.value, table_id)
        new_entry.set_column(RequestsTableColumn.ID_SOURCE.value, manager_alias)
        new_entry.set_column(RequestsTableColumn.ID_DEST.value, agent_alias)
        #print("a imprimir nova linha: " + str(new_entry))
        with global_requests_table_lock:
            global_requests_table.append(new_entry)
        return ResponseStatus.SUCCESS
    else:
        # linha já existe
        # erro se estivermos a definir o id pela primeira vez...
        if table_column == RequestsTableColumn.TYPE_OPER.value:
            return ResponseStatus.ID_ALREADY_EXISTS
        
        # temos que ver se este manager é o autorizado
        # e o agente está correto
        with global_requests_table_lock:
            row:RequestsTableEntry = global_requests_table[row_index]
            if row.idSource==manager_alias and row.idDest==agent_alias:
                # será que o objeto está definido na totalidade?
                if hasattr(row, "oidArg"):
                    if row.oidArg == decrypted_value:
                        return ResponseStatus.SAME_OID_ALREADY_EXISTS
                    return ResponseStatus.DIFFERENT_OID_ALREADY_EXISTS
                
                # a unica possibilidade é guardar o oidArg...
                # no futuro pode-se por isto mais modular
                global_requests_table[row_index].oidArg = decrypted_value
                
                # à partida, vai estar completely set, isto é só um safeguard
                if global_requests_table[row_index].isCompletelySet():
                    global_requests_table[row_index].statusOper = RequestStatus.WAITING_FOR_QUERY
                else:
                    global_requests_table[row_index].statusOper = RequestStatus.INCOMPLETE

                #print("a imprimir linha: " + str(global_requests_table[row_index]))
                return ResponseStatus.SUCCESS

        print("Manager nao esta autorizado a fazer essa operacao...")
        return ResponseStatus.UNAUTHORIZED_OPERATION

"""Devolve o valor (valueArg) de um dado objeto guardado
Caso não exista (ou ocorram outros problemas), devolve None"""
def get_object_from_table(table_id):
    row_index = get_row_index_by_id(table_id)
    if row_index is None:
        return ResponseStatus.INVALID_TABLE_OID, None
    with global_requests_table_lock:
        obj = global_requests_table[row_index]
        if obj.statusOper == RequestStatus.VALID:
            return ResponseStatus.SUCCESS, obj.valueArg
    return ResponseStatus.FETCH_ERROR, obj.valueArg

"""Devolve a chave guardada para o manager dado.
Se não existir, devolve None"""
def get_manager_key_from_alias(manager_alias:str):
    for e in global_keys_table:
        if e.manager_alias == manager_alias:
            return e.key
    return None

"""Devolve um id da tabela ainda não usado.
Caso não o encontre (praticamente impossível),
devolve um já existente (o que faz com que os
managers desistam de fazer queries)"""
def generate_unused_table_id()->int:
    with global_requests_table_lock:
        used_ids = [e.idOper for e in global_requests_table]
    # escolher o número menor
    for e in range(RequestsTable.minId, RequestsTable.maxId+1):
        if e not in used_ids:
            return e
    # se nao for possivel encontrar nenhum, escolhe
    # o 1 arbitrariamente
    return 

def handle_manager_request(request:SNMPPacket) -> bytes:
    """ Recebe um pacote SNMP e devolve a resposta
        (Pacote SNMP para bytes) """

    respond_flag = True # por norma, é para responder
    # exceto quando a chave de decifra está inválida
    response = None
    status = None

    packet_oid = request.object_identifier
    manager_alias = request.manager

    # Ver se o manager tem uma chave guardada
    manager_secret_key = get_manager_key_from_alias(
        manager_alias
    )
    if manager_secret_key is None:
        print("Chave do manager " + manager_alias + " nao guardada...")
        respond_flag = False
    elif manager_alias in global_manager_blacklist:
        print("Manager " + manager_alias + " na blacklist...")
        respond_flag = False
    else:
        table_id,table_column = get_table_id_and_column_from_oid(packet_oid)
        if request.packet_type == PacketType.SET_REQUEST:
            if table_id is None:
                # oid mal formatado...
                print("Erro de formatacao no oid " + packet_oid)
                status = ResponseStatus.INVALID_TABLE_OID
            else:
                # ver se o value fornecido no pedido é válido
                # (tentar decifrá-lo)
                decrypted_value_bytes = CryptoOperation.aes_decryption(
                    request.value, manager_secret_key)
                if decrypted_value_bytes is None:
                    # Nao vai responder por questoes de segurança...
                    # Se for um atacante, a informaçao que a chave é inválida
                    # pode ser benéfica
                    respond_flag = False
                    global_manager_blacklist.append(manager_alias)
                    print("Chave inválida...")
                else:
                    decrypted_value = decrypted_value_bytes.decode()
                    #print("Valor do pedido: " + decrypted_value)

                    status = save_request_in_table(table_id, table_column, decrypted_value, 
                    manager_alias, request.agent)
                    if status == ResponseStatus.ID_ALREADY_EXISTS:
                        # fornecer outro ID para o manager tentar outra vez
                        response = str(generate_unused_table_id())
                        print("NOVO ID: " + response)

        elif request.packet_type==PacketType.GET_REQUEST or request.packet_type==PacketType.GET_NEXT_REQUEST:
            # buscar valor à tabela
            status, response = get_object_from_table(table_id)
        else:
            respond_flag = False
            global_manager_blacklist.append(manager_alias)
            print("Tipo de pedido invalido...")


    if respond_flag:
        response_snmp_packet = SNMPPacket(
            packet_id=request.packet_id,
            comm_str=COMM_STRING,
            packet_type=PacketType.RESPONSE,
            oid=None,
            value=response,
            manager=manager_alias,
            agent=request.agent,
            secret_key=manager_secret_key,
            response_status=status
        )
        #print("A responder: " + str(response.value))
        response_bytes = response_snmp_packet.convert_to_bytes()
        UDPCommunication.send_UDP(response_bytes, SEND_TO_PORT)

# 0) definir objetos
#ObjectType(ObjectIdentity('netSnmp.11', 'secSecretKeyValue'), 2078136525)

def fill_table_with_agent_response():
    now = datetime.now()
    with global_requests_table_lock:
        for req in global_requests_table:
            if req.statusOper == RequestStatus.WAITING_FOR_QUERY:
                if req.typeOper == PacketType.GET_REQUEST.value:
                    status,result = get_request_scalar(req.oidArg)
                elif req.typeOper == PacketType.GET_NEXT_REQUEST.value:
                    status,result = get_next_request_scalar(req.oidArg)
                else:
                    print("Request type " + str(req.typeOper) + " not handled!")
                    req.statusOper = RequestStatus.INVALID
                    continue # passa para o proximo 
                
                # definir (value,) tipo, tamanho, timestamp
                # TODO definir tipo
                req.valueArg = result
                req.sizeArg = len(req.valueArg)
                req.responseTimestamp = now
                
                if status != ResponseStatus.SUCCESS:
                    req.statusOper = RequestStatus.INVALID
                    print("Erro ao fazer query (" + req.valueArg + ")")
                else:
                    req.statusOper = RequestStatus.VALID

"""Vai sempre apagar pedidos não válidos
que tenham acontecido há mais de x seg"""
def clean_table():
    now = datetime.now()
    with global_requests_table_lock:
        for req in global_requests_table:
            status = req.statusOper
            if status == RequestStatus.INVALID or status == RequestStatus.EXPIRED:
                if req.hasTimestampSet():
                    # ver se ja passou o tempo
                    stored_date = req.responseTimestamp

                    if (stored_date + timedelta(seconds=DELETE_NON_VALID_TABLE_ENTRY_DELAY)) < now:
                        global_requests_table.remove(req)
                else:
                    global_requests_table.remove(req)


def handle_requests_thread():
    print("Thread que trata dos pedidos iniciada!")

    while True:
        manager_request = SNMPPacket.convert_to_packet(
            global_manager_requests_queue.get()
        )
        print("Pedido do manager: " + str(manager_request))

        handle_manager_request(manager_request)

def fill_table_with_response_thread():
    print("Thread que trata de por as respostas na tabela iniciada!")
    while True:
        fill_table_with_agent_response()
        sleep(FILL_TABLE_DELAY)

def clean_table_thread():
    print("Thread que vai limpando a tabela iniciada!")
    while True:
        sleep(CLEAN_TABLE_DELAY)
        clean_table()

def main():
    # começar thread que trata dos pedidos
    t = Thread(target=handle_requests_thread)
    t.start()

    # começar thread que preenche a tabela
    t = Thread(target=fill_table_with_response_thread)
    t.start()

    # começar thread que vai limpando a tabela
    t = Thread(target=clean_table_thread)
    t.start()

    # Thread principal apenas coloca o que recebe numa Queue para a 
    # outra thread tratar
    recv_packet = UDPCommunication.recv_UDP_block(LISTEN_PORT, RECV_BUFF_SIZE)
    while True:
        global_manager_requests_queue.put(
            next(recv_packet)
        )

if __name__ == "__main__":
    # Ler chave privada para comunicar com manager
    parser = ConfigParser()
    parser.read(KEY_STORAGE_FILENAME)

    # Acrescentar chaves à tabela
    for man,key in parser.items(KEY_FILE_SECTION):
        global_keys_table.append(
            KeysTableEntry(
                manager_alias=man,
                key=key
            )
        )
    
    main()