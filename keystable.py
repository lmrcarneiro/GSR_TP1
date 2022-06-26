class KeysTableEntry:
    def __init__(self, manager_alias:str, key:str):
        self.manager_alias:str = manager_alias
        self.key:bytes = bytes(key,"utf-8")