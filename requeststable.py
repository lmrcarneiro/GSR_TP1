from enum import Enum
from Crypto.Random.random import randint

class RequestsTableColumn(Enum):
	ID_OPER = "idOper"
	TYPE_OPER = "typeOper"
	ID_SOURCE = "idSource"
	ID_DEST = "idDest"
	OID_ARG = "oidArg"

class RequestsTable:
    """Define a estrutura de dados usada na MIB-SEC para guardar pedidos"""
    name:str = "TableReq"
    idOperDigits:int = 5
    defaultTtl:int = 120

    # Para criar o id aleatório da operação
    minId = 10 ** (idOperDigits-1)
    maxId = (10 ** idOperDigits) -1

    @classmethod
    def get_random_operation_id(cls):
        return randint(cls.minId, cls.maxId)

class RequestsTableEntry:
    def __init__(self, idOper:int):
        self.idOper:int = idOper
        #self.typeOper:int = typeOper
        #self.idSource:str = idSource
        #self.idDest:str = idDest
        #self.oidArg:str = oidArg
        #self.valueArg:str = valueArg
        #self.typeArg:int = typeArg
        #self.sizeArg:int = sizeArg
        #self.ttlOper:int = ttlOper
        #self.statusOper:int = statusOper
    
    def set_column(self, column_name:str, value):
        # O que o manager define
        if column_name == RequestsTableColumn.ID_OPER.value:
            self.idOper = value
        elif column_name == RequestsTableColumn.TYPE_OPER.value:
            self.typeOper = value
        elif column_name == RequestsTableColumn.ID_SOURCE.value:
            self.idSource = value
        elif column_name == RequestsTableColumn.ID_DEST.value:
            self.idDest = value
        elif column_name == RequestsTableColumn.OID_ARG.value:
            self.oidArg = value
        # O que o proxy define ao responder
        # ...
        else:
            print(column_name + " invalido!")
    
    def __str__(self):
        s = "ID: " + str(self.idOper) + ", Type: " + self.typeOper
        if hasattr(self, "idSource"): s += " " + self.idSource
        if hasattr(self, "idDest"): s += " " + self.idDest
        if hasattr(self, "oidArg"): s += " OID: " + self.oidArg + "\n"
        return s