class MIBsecRow:
    """Define a estrutura de dados usada na SEC-MIB"""

    idOperDigits:int = 5
    defaultTtl:int = 120

    def __init__(self, idOper:int, typeOper:int, idSource:str, idDest:str, oidArg:str, valueArg:str, typeArg:int, sizeArg:int, ttlOper:int, statusOper:int):
        self.idOper:int = idOper
        self.typeOper:int = typeOper
        self.idSource:str = idSource
        self.idDest:str = idDest
        self.oidArg:str = oidArg
        self.valueArg:str = valueArg
        self.typeArg:int = typeArg
        self.sizeArg:int = sizeArg
        self.ttlOper:int = ttlOper
        self.statusOper:int = statusOper