from base64 import encode
from cProfile import label
import json
import subprocess
from slither import Slither
import slither
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.solidity_types.array_type import ArrayType 
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.declarations.structure import Structure
from slither.core.declarations.enum_contract import EnumContract
from slither.core.declarations.structure_contract import StructureContract
from slither.core.declarations.contract import Contract
from slither.core.variables.structure_variable import StructureVariable
import sys
import math 
import re 
import os

import argparse


def filtercompilerversion(compiler_version):
    if compiler_version.find("commit")!=-1:
        compiler_version = compiler_version.split("+commit")[0].split("v")[1]
    if compiler_version.find("night")!=-1:
        compiler_version = compiler_version.split("-night")[0]
        if compiler_version.find("v")!=-1:
            compiler_version = compiler_version.split("v")[1]
    if compiler_version in [f"0.4.{i}" for i in range(25)]:
        compiler_version = "0.4.25"
    elif compiler_version.find("0.3")!=-1:
        compiler_version = "0.4.25"
    return compiler_version

def installSolc(solcVersion):
    solcVersion = filtercompilerversion(solcVersion)
    subprocess.run(["solc-select","install", solcVersion])
    subprocess.run(["solc-select","use", solcVersion])

dynamicArrayRegex = re.compile(r"(\w+)\[\]")
fixedArrayRegex = re.compile(r"(\w+)\[([0-9]+)\]")
def compute_type_info(vartype, _type_info, contract):
    type_ = str(vartype)
    if type_ == "bool":
        _type_info[contract.name][type_]  = dict(encoding="inplace", label="bool", numberOfBytes =vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "uint256":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="uint256", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "uint128":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="uint128", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "uint64":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="uint64", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "uint32":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="uint32", numberOfBytes =vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "uint16":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="uint16", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "uint8":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="uint8", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "int256":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="int256", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "int128":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="int128", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "int64":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="int64", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "int32":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="int32", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "int16":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="int16", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "int8":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="int8", numberOfBytes =vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "address":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="address", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "bytes":
        _type_info[contract.name][type_]  =  dict(encoding="bytes", label="bytes", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "string":
        _type_info[contract.name][type_]  =  dict(encoding="bytes", label="string", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "bytes32":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="bytes32", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "bytes16":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="bytes16", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "bytes1":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="bytes1", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif type_ == "enum":
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="enum", numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
    elif isinstance(vartype, ArrayType):
        arraytype: ArrayType = vartype
        # if arraytype.is_fixed_array:
        if arraytype.length != None:
            base = arraytype.type 
            size = int(str(arraytype.length))
            # m = fixedArrayRegex.match(type_)
            # base = m.groups()[0]
            # size = m.groups()[1]
            compute_type_info(base, _type_info, contract)
            if _type_info[contract.name][str(base)]['numberOfBytes'] > 32:
                numberOfBytes = 32 * size * math.ceil(_type_info[str(base)]['numberOfBytes'])/32
            else:
                numInASlot = int(32/_type_info[contract.name][str(base)]['numberOfBytes'])
                numberOfBytes = 32 * math.ceil(size/numInASlot)
            _type_info[contract.name][type_]  =  dict(base = str(base), encoding= "fixed_array", label=type_, numberOfBytes=numberOfBytes, length=size, newSlot = True, isNormalType=False)
        else:
            # assert arraytype.is_dynamic_array, "must be dynamic array"
            assert arraytype.length == None, "must be dynamic array"
            base = arraytype.type 
            # m = dynamicArrayRegex.match(type_)
            # base = m.groups()[0]
            compute_type_info(base, _type_info, contract)
            _type_info[contract.name][type_]  =  dict(base = str(base), encoding= "dynamic_array", label=type_, numberOfBytes=vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=False)
    elif isinstance(vartype, MappingType):
        type_from = vartype.type_from
        type_to = vartype.type_to
        _type_info[contract.name][type_] =  dict(encoding="mapping", key=str(type_from), label=type_, value=str(type_to), numberOfBytes=32, newSlot = True, isNormalType=False)
        compute_type_info(type_from, _type_info, contract)
        compute_type_info(type_to, _type_info, contract)
    elif isinstance(vartype, UserDefinedType): 
            # and isinstance(var.type.type, EnumContract):
            # print(type(vartype.type))
            if isinstance(vartype.type, EnumContract):
                # print(type(vartype.storage_size[0]))
                _type_info[type_] =  dict(encoding="enum", label="enum_"+type_, numberOfBytes=vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=True)
            elif isinstance(vartype.type, StructureContract):
                structure = vartype.type
                # print("struct!!!", str(vartype), vartype.storage_size)
                name = structure.name 
                elems = structure.elems_ordered
                members = []
                # _index = 0
                # _slot = 0
                # _offset = 0
                # totalsize = 0
                for elem in elems:
                    # _astid = _index
                    # _size, _new_slot = vartype.storage_size
                    # totalsize += _size
                    # if _new_slot:
                    #     if _offset > 0:
                    #         _slot += 1
                    #         _offset = 0
                    # elif _size + _offset > 32:
                    #         _slot += 1
                    #         _offset = 0
                    
                    _type_ = str(elem.type)


                    members.append(dict(
                                # astId = _astid,
                                contract = contract.name,
                                label = elem.name,
                                # offset = _offset,
                                # slot = _slot,
                                type = _type_))
                    # _index += 1
                    if _type_ not in _type_info:
                        compute_type_info(elem.type, _type_info, contract)
                    else:
                        pass 
                # _type_info[contract.name][type_] = dict(encoding = "inplace", label=str(vartype), members=members,numberOfBytes = totalsize)
                _type_info[contract.name][type_] = dict(encoding = "struct", label=str(vartype), members=members, numberOfBytes = vartype.storage_size[0], newSlot = vartype.storage_size[1], isNormalType=False)
            elif isinstance(vartype.type, Contract):
                _type_info[contract.name][type_] =  dict(encoding="inplace", label="address", numberOfBytes=20, newSlot = True, isNormalType=True)
            else:
                # assert False, type_ + " is currently not supported"     
                print (type_ + " is currently not supported")
    # debug
    elif type_[:4] == "uint":
        intNum = int(type_[4:])
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="enum", numberOfBytes = math.ceil(intNum/8), newSlot=False, isNormalType=True)
    elif type_[:3] == "int":
        intNum = int(type_[3:])
        _type_info[contract.name][type_]  =  dict(encoding="inplace", label="enum", numberOfBytes = math.ceil(intNum/8), newSlot=False, isNormalType=True)
    else:
        # assert False, type_ + " is currently not supported"
        print (type_ + " is currently not supported")

def compute_storage_layout(self):
    if not hasattr(self, "_type_info") or self._type_info is None:
        self._type_info = dict()
        self._storage = dict() 
    for contract in self.contracts:
        if contract.name not in self._type_info:
            self._type_info[contract.name] = dict()
        if contract.name not in self._storage:
            self._storage[contract.name] = []
        slot = 0
        offset = 0
        index = 0
        for var in contract.state_variables_ordered:
            if var.is_constant or (hasattr(var, "is_immutable") and  var.is_immutable):
                continue    
            astnode_id = index
            size, new_slot = var.type.storage_size
            # print(var, size, new_slot, var.type._compute_line, dir(var.type))
            if new_slot:
                if offset > 0:
                    slot += 1
                    offset = 0
            elif size + offset > 32:
                slot += 1
                offset = 0
            type_ = str(var.type)
            self._storage[contract.name].append(dict(
                astId = astnode_id,
                contract = contract.name,
                label = var.contract.name+"_own_" + var.name if var.contract.name != contract.name else var.name,
                offset = offset,
                # slot = str(slot),
                slot = slot,
                type = type_
            ))
            compute_type_info(var.type, self._type_info, contract)
            if new_slot:
                # slot += math.ceil(size / 32)
                slot += math.ceil(self._type_info[contract.name][str(var.type)]["numberOfBytes"]/32)
            else:
                offset += size
            index += 1

def extractStorageLayout(sol_file, contractsPath, outputStorageFile, contractName=None, compilerVersion=None):

    contractDict = dict()
    # if outputStorageFile is not None and os.path.exists(outputStorageFile):
    #     print("exising storageLayout")
    #     with open(outputStorageFile, "r") as f:
    #         storageLayout_dict = json.load(f)
    #     return storageLayout_dict
    
    # installSolc(compilerVersion)

    ori = os.getcwd()
    # print(ori)
    os.chdir(contractsPath)
    # print(os.getcwd(), sol_file)
    # try:
    s = Slither(sol_file)
    compilation_units = s.compilation_units
    # print("length of compilation_units", len(compilation_units))
    for compilation_unit in compilation_units:
        compute_storage_layout(compilation_unit)
        for contractName in compilation_unit._storage:
            # for typeName in compilation_unit._type_info[contractName]:
            #     compilation_unit._type_info[contractName][typeName]["numberOfBytes"] = int(compilation_unit._type_info[contractName][typeName]["numberOfBytes"])
            contractDict[contractName] =  dict(storage = compilation_unit._storage[contractName], types = compilation_unit._type_info[contractName])
    # except:
    #     print("slither analysis error")
    os.chdir(ori)
    # print(contractDict)
    if outputStorageFile is not None:
        with open(outputStorageFile, "w") as f:
            json.dump(contractDict, f)

    # print(str(compilation_units))
    # with open(outputStorageFile+".json", "w") as f:
        # json.dump(compilation_units,f)
    
    return contractDict

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', dest='version', type=str)
    parser.add_argument('--contract_name', dest='contract_name', type=str)
    parser.add_argument('--output_path', dest='output_path', type=str)
    parser.add_argument('--sol_file', dest='sol_file', type=str)
    parser.add_argument('--contract_path', dest='contract_path', type=str)
    args = parser.parse_args()
    return args

if __name__ == "__main__":

    args = get_args()
    version = args.version
    contractName = args.contract_name
    outputStorageFile = args.output_path
    sol_file = args.sol_file
    contractsPath = args.contract_path
    # version = "v0.4.24"
    # contractName = "TestToken"
    # outputStorageFile = "test2_storage.json"
    # sol_file = "test2.sol"
    # contractsPath = "./"
    extractStorageLayout(sol_file, contractsPath, outputStorageFile)