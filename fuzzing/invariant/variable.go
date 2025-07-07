package invariant

import (
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	crypto "github.com/ethereum/go-ethereum/crypto"
)

type StateValue struct {
	Value    any
	Type     string
	Base     string
	IsChange bool

	// for debug
	Source string
}

type CacheStateValueInfo struct {
	VarName string
	Value   any
	Type    string
	Key     common.Hash
	Index   int
}

func (s *StateValue) Cmp(ss *StateValue) int {
	if s.Type != ss.Type {
		return -2
	} else {
		if s.Type == "uint256" {
			return s.Value.(*big.Int).Cmp(ss.Value.(*big.Int))
		} else if s.Type == "bool" {
			if s.Value.(bool) == ss.Value.(bool) {
				return 0
			} else {
				return -1
			}
		} else if s.Type == "address" {
			if s.Value == ss.Value {
				return 0
			} else {
				return -1
			}
		} else if s.Type == "fixedBytesTy" || s.Type == "bytes" {
			if string(s.Value.([]byte)) == string(ss.Value.([]byte)) {
				return 0
			} else {
				return -1
			}
		} else if s.Type == "hash" {
			if s.Value.(common.Hash).String() == ss.Value.(common.Hash).String() {
				return 0
			} else {
				return -1
			}
		} else {
			panic(fmt.Sprintf("unsupport type in StateValue.Cmp: %v", s.Type))
		}
	}
}

func (s *StateValue) GetValueStr() string {
	var varValueStr string
	if strings.Contains(s.Type, "uint") || strings.Contains(s.Type, "int") {
		varValueStr = s.Value.(*big.Int).String()
	} else if s.Type == "address" {
		// varValueStr = s.Value.(common.Address).String()
		varValueStr = new(big.Int).SetBytes(s.Value.(common.Address).Bytes()).String()
	} else {
		// TODO
		panic("unhandled type" + s.Type)
	}
	return varValueStr
}

func (s *StorageExtractor) FlatStateVariables(stateVariableMap map[string]*StateValue, interestingValues map[common.Hash][]*ArgValue) map[string]*StateValue {
	flatedStateVariables := make(map[string]*StateValue)
	for varName, stateValue := range stateVariableMap {
		for newName, newStateValue := range s.flatStateVariable(varName, stateValue, interestingValues) {
			flatedStateVariables[newName] = newStateValue.(*StateValue)
		}
	}
	return flatedStateVariables
}

func (s *StorageExtractor) flatStateVariable(varName string, stateValue *StateValue, interestingValues map[common.Hash][]*ArgValue) map[string]any {
	flatedStateVariables := make(map[string]any)
	varType := s.getVarType(stateValue.Type)
	if varType.IsNormalType {
		flatedStateVariables[varName] = stateValue
	} else if stateValue.Type == "mapping" {
		for key, item := range stateValue.Value.(map[common.Hash]*StateValue) {
			for _, argValue := range interestingValues[key] {
				tempPrefix := fmt.Sprintf("%v[%v]", varName, argValue.Name)
				for newName, newStateValue := range s.flatStateVariable(tempPrefix, item, interestingValues) {
					flatedStateVariables[newName] = newStateValue.(*StateValue)
				}
			}
		}
	} else if stateValue.Type == "struct" {
		for key, item := range stateValue.Value.(map[string]*StateValue) {
			temp := fmt.Sprintf("%v.%v", varName, key)
			for newName, newStateValue := range s.flatStateVariable(temp, item, interestingValues) {
				flatedStateVariables[newName] = newStateValue.(*StateValue)
			}
		}
	} else if stateValue.Type == "array" {
		// ignore the case of []struct
		var tmpArray []any
		if stateValue.Base != "array" && stateValue.Base != "struct" && stateValue.Base != "mapping" {
			for _, elem := range stateValue.Value.([]*StateValue) {
				tmpArray = append(tmpArray, elem.Value)
			}
			newStateValue := StateValue{
				Value: tmpArray,
				Type:  "array",
				Base:  stateValue.Base,
			}
			flatedStateVariables[varName] = &newStateValue
		}
		// flatedStateVariables[varName] = stateValue
	} else {
		fmt.Println("Error in flatStateVariable")
	}
	return flatedStateVariables
}

func (s *StorageExtractor) LoadStateVariables(slotMap map[common.Hash]common.Hash, interestingValues map[common.Hash][]*ArgValue) (map[string]*StateValue, map[common.Hash]bool) {
	stateVarableMap := make(map[string]*StateValue)
	touchedSlots := make(map[common.Hash]bool)
	for _, storageInfo := range s.storageLayout.Storage {
		stateVarType := s.getVarType(storageInfo.Type)
		tmpSlot := common.BigToHash(big.NewInt(int64(storageInfo.Slot)))
		tmpValue := s.getStateVariable(tmpSlot, storageInfo.Type, storageInfo.Offset, stateVarType.NumberOfBytes, slotMap, interestingValues, touchedSlots)
		if tmpValue != nil {
			stateVarableMap[storageInfo.Label] = tmpValue
		}
	}
	return stateVarableMap, touchedSlots
}

func (s *StorageExtractor) getVarType(varType string) VarType {
	if _, ok := s.storageLayout.Types[varType]; ok {
		return s.storageLayout.Types[varType]
	}
	return VarType{
		Encoding:      "inplace",
		Label:         "bytes32",
		NumberOfBytes: 32,
	}
}

func addSlot(slot common.Hash, num int) common.Hash {
	oriSlot := slot.Big()
	newSlot := new(big.Int).Add(oriSlot, big.NewInt(int64(num)))
	return common.BigToHash(newSlot)
}

func (s *StorageExtractor) getStateVariable(slot common.Hash, stateVariableType string, offset, numberOfBytes int, slotMap map[common.Hash]common.Hash, interestingValues map[common.Hash][]*ArgValue, touchedSlots map[common.Hash]bool) *StateValue {
	stateVarType := s.getVarType(stateVariableType)
	if stateVarType.Encoding == "dynamic_array" || stateVarType.Encoding == "fixed_array" {
		var tmpList []*StateValue
		var length int
		var thisSlot common.Hash
		if stateVarType.Encoding == "dynamic_array" {
			tmpLength := s.getSlotValue(slot, offset, numberOfBytes, "int256", slotMap, touchedSlots)
			if tmpLength != nil {
				length = int(tmpLength.(*big.Int).Int64())
			}
			thisSlot = common.BytesToHash(crypto.Keccak256(slot.Bytes()))
		} else {
			thisSlot = slot
			length = stateVarType.Length
		}

		elementType := stateVarType.Base
		elementVarType := s.getVarType(elementType)
		numOfBytes := elementVarType.NumberOfBytes

		offset := 0
		newSlot := stateVarType.NewSlot
		for index := int(0); index < length; index++ {
			// if loadedByteInSlot+numOfBytes > 32 {
			// 	loadedByteInSlot = 0
			// 	thisSlot = addSlot(thisSlot, 1)
			// }
			if newSlot {
				if offset > 0 {
					thisSlot = addSlot(thisSlot, 1)
					offset = 0
				}
			} else if offset+numOfBytes > 32 {
				thisSlot = addSlot(thisSlot, 1)
				offset = 0
			}

			tmpValue := s.getStateVariable(thisSlot, elementType, offset, numOfBytes, slotMap, interestingValues, touchedSlots)

			if newSlot {
				thisSlot = addSlot(thisSlot, int(math.Ceil(float64(numOfBytes)/32)))
			} else {
				offset += numOfBytes
			}
			if tmpValue != nil {
				tmpList = append(tmpList, tmpValue)
			}
		}
		if len(tmpList) > 0 {
			return &StateValue{
				Value: tmpList,
				Type:  "array",
				Base:  tmpList[0].Type,
			}
		}
		return nil
	} else if stateVarType.Encoding == "mapping" {
		mappingDict := make(map[common.Hash]*StateValue)
		for key := range interestingValues {
			targetSlot := calMappingKey(key, slot)
			tmpValue := s.getStateVariable(targetSlot, stateVarType.Value, 0, 32, slotMap, interestingValues, touchedSlots)
			if tmpValue != nil {
				// for _, argValue := range interestingValues[key] {
				// 	mappingDict[argValue.Name] = tmpValue
				// }
				mappingDict[key] = tmpValue
			}
		}
		if len(mappingDict) > 0 {
			return &StateValue{
				Value: mappingDict,
				Type:  "mapping",
			}
		}
		return nil
	} else if stateVarType.Encoding == "struct" {
		offset := 0
		thisSlot := slot
		structMap := make(map[string]*StateValue)
		for _, member := range stateVarType.Members {
			memberType := member.Type
			memberVarType := s.getVarType(memberType)
			numOfBytes := memberVarType.NumberOfBytes
			newSlot := memberVarType.NewSlot
			// if loadedByteInSlot+numOfBytes > 32 {
			// 	loadedByteInSlot = 0
			// 	thisSlot = addSlot(thisSlot, 1)
			// }
			if newSlot {
				if offset > 0 {
					thisSlot = addSlot(thisSlot, 1)
					offset = 0
				}
			} else if offset+numOfBytes > 32 {
				thisSlot = addSlot(thisSlot, 1)
				offset = 0
			}

			memberValue := s.getStateVariable(thisSlot, memberType, offset, numOfBytes, slotMap, interestingValues, touchedSlots)
			if memberValue != nil {
				structMap[member.Label] = memberValue
			}

			if newSlot {
				thisSlot = addSlot(thisSlot, int(math.Ceil(float64(numOfBytes)/32)))
			} else {
				offset += numOfBytes
			}
		}
		if len(structMap) > 0 {
			return &StateValue{
				Value: structMap,
				Type:  "struct",
			}
		}
		return nil
	} else if stateVarType.Encoding == "inplace" || stateVarType.Encoding == "bytes" {
		tmpValue := s.getSlotValue(slot, offset, numberOfBytes, stateVarType.Label, slotMap, touchedSlots)
		if tmpValue != nil {
			return &StateValue{
				Value: tmpValue,
				Type:  stateVarType.Label,
			}
		}
		return nil
	} else {
		fmt.Println("unknown", stateVariableType)
		return nil
	}
}

func (s *StorageExtractor) getSlotValue(slot common.Hash, offset, numberOfBytes int, valueType string, slotMap map[common.Hash]common.Hash, touchedSlots map[common.Hash]bool) any {
	if _, ok := slotMap[slot]; !ok {
		return nil
	}
	touchedSlots[slot] = true
	tmpValue := slotMap[slot]
	slotValue := tmpValue[32-(offset+numberOfBytes) : 32-offset]
	slotValue = common.BytesToHash(slotValue).Bytes()
	// fmt.Println(slot, slotMap[slot], offset, numberOfBytes, valueType, slotValue)
	// fmt.Println(len(slotValue))
	// value :=  + slotValue
	if valueType == "string" {
		return nil
	} else if valueType == "bytes" {
		return nil
	} else {
		tmpType, err := abi.NewType(valueType, valueType, []abi.ArgumentMarshaling{})
		if err != nil {
			fmt.Println("Error of NewType in getSlotValue", err)
		}
		args := abi.Arguments{abi.Argument{
			Name: "tmp",
			Type: tmpType,
		}}
		value, err := args.Unpack(slotValue)
		if err != nil {
			fmt.Println("Error of Unpack in getSlotValue", err)
		}
		return value[0]
	}
}

func FitStateVariables(preStateVariableMap, postStateVariableMap map[string]*StateValue) (map[string]*StateValue, map[string]bool) {
	mergedStateVariables := make(map[string]*StateValue)
	varNameList := make(map[string]bool)
	for varName := range preStateVariableMap {
		varNameList[varName] = true
		preVarName := fmt.Sprintf("pre(%v)", varName)
		postVarName := fmt.Sprintf("post(%v)", varName)
		mergedStateVariables[preVarName] = preStateVariableMap[varName]
		if _, ok := postStateVariableMap[varName]; !ok {
			if preStateVariableMap[varName].Type == "array" {
				mergedStateVariables[postVarName] = &StateValue{
					Value: []any{},
					Type:  "array",
				}
			} else {
				panic("error in FitStateVariables")
			}
		} else {
			mergedStateVariables[postVarName] = postStateVariableMap[varName]
		}
	}

	for varName := range postStateVariableMap {
		varNameList[varName] = true
		preVarName := fmt.Sprintf("pre(%v)", varName)
		postVarName := fmt.Sprintf("post(%v)", varName)
		if _, ok := mergedStateVariables[postVarName]; !ok {
			mergedStateVariables[postVarName] = postStateVariableMap[varName]
			if postStateVariableMap[varName].Type == "array" {
				mergedStateVariables[preVarName] = &StateValue{
					Value: []any{},
					Type:  "array",
				}
			} else {
				panic("error in FitStateVariables")
			}
		}
	}
	return mergedStateVariables, varNameList
}

type StorageLayout struct {
	Storage []Storage          `json:"storage"`
	Types   map[string]VarType `json:"types"`
}

type Storage struct {
	AstId    int    `json:"astId"`
	Contract string `json:"contract"`
	Label    string `json:"label"`
	Offset   int    `json:"offset"`
	Slot     int    `json:"slot"`
	Type     string `json:"type"`
}

type VarType struct {
	Encoding      string    `json:"encoding"`
	Key           string    `json:"key"`
	Label         string    `json:"label"`
	NumberOfBytes int       `json:"numberOfBytes"`
	Value         string    `json:"value"`
	Members       []Storage `json:"members"`
	Base          string    `json:"base"`
	Length        int       `json:"length"`
	NewSlot       bool      `json:"newSlot"`
	IsNormalType  bool      `json:"isNormalType"`
}

func getArgValueMap(callFrame *CallFrame, interestingValues map[common.Hash][]*ArgValue) map[string]ArgValue {

	var (
		method      *abi.Method
		err         error
		inputValues []any
	)
	// Resolve our contract names, as well as our method and its name from the code contract.
	codeContractAbi := callFrame.GetCodeContractAbi()
	input := callFrame.GetInput()
	if codeContractAbi != nil {
		if callFrame.IsContractCreation() {
			method = &codeContractAbi.Constructor
		} else {
			method, err = codeContractAbi.MethodById(input)
		}
	}

	argValueMap := make(map[string]ArgValue)
	if method != nil {
		// Determine what buffer will hold our ABI data.
		// - If this a contract deployment, constructor argument data follows code, so we use a different buffer the
		//   tracer provides.
		// - If this is a normal call, the input data for the call is used, with the 32-bit function selector sliced off.
		abiDataInputBuffer := make([]byte, 0)
		if callFrame.IsContractCreation() {
			abiDataInputBuffer = callFrame.GetConstructorArgsData()
		} else if len(input) >= 4 {
			abiDataInputBuffer = input[4:]
		}
		// Unpack our input values and obtain a string to represent them
		inputValues, err = method.Inputs.Unpack(abiDataInputBuffer)
		if err == nil {
			// find interesting values
			argValueMap, err = TravelABIArgs(method.Inputs, inputValues, interestingValues)
			if err != nil {
				fmt.Println("error in TravelABIArgs")
			}
		}
	}
	return argValueMap
}

func GetDynamicVariables(callFrame *CallFrame, interestingValues map[common.Hash][]*ArgValue) (map[string]*StateValue, map[string]bool) {
	currentContract := callFrame.GetTo()
	preFlatedVariables := make(map[string]*StateValue)
	postFlatedVariables := make(map[string]*StateValue)
	storageExtractor := callFrame.GetStorageExtractor()
	if storageExtractor != nil {
		preStorage, existPreStorage := callFrame.GetStorage(currentContract, "pre")
		if existPreStorage {
			preStateVariableMap, _ := storageExtractor.LoadStateVariables(preStorage, interestingValues)
			preFlatedVariables = storageExtractor.FlatStateVariables(preStateVariableMap, interestingValues)
		}
		postStorage, existPostStorage := callFrame.GetStorage(currentContract, "post")
		if existPostStorage {
			postStateVariableMap, _ := storageExtractor.LoadStateVariables(postStorage, interestingValues)
			postFlatedVariables = storageExtractor.FlatStateVariables(postStateVariableMap, interestingValues)
		}
	}
	// attach
	attachEtherBalance(callFrame, callFrame.PreState, preFlatedVariables)
	attachEtherBalance(callFrame, callFrame.PostState, postFlatedVariables)
	mergedStateVariables, varNameList := FitStateVariables(preFlatedVariables, postFlatedVariables)
	return mergedStateVariables, varNameList
}

func attachEtherBalance(callFrame *CallFrame, state State, dynamicVariables map[string]*StateValue) {
	if state[callFrame.From] != nil && state[callFrame.To] != nil {
		etherBalanceSender := fmt.Sprintf("etherBalance[%s]", "sender")
		dynamicVariables[etherBalanceSender] = &StateValue{
			Value: state[callFrame.From].Balance,
			Type:  "uint256",
		}
		etherBalanceCallee := fmt.Sprintf("etherBalance[%s]", "callee")
		dynamicVariables[etherBalanceCallee] = &StateValue{
			Value: state[callFrame.To].Balance,
			Type:  "uint256",
		}
	}
}

func GetTestMergedStateVariables(callFrame CallFrame) map[string]*StateValue {
	testMergedStateVariables := make(map[string]*StateValue)
	testMergedStateVariables["post(balances[msg.sender])"] = &StateValue{
		Value: big.NewInt(1000),
		Type:  "uint256",
	}
	return testMergedStateVariables
}

func GetVariables(callFrame *CallFrame) map[string]*StateValue {
	interestingValues := make(map[common.Hash][]*ArgValue)
	var argValueMap map[string]ArgValue
	argValueMap = getArgValueMap(callFrame, interestingValues)
	currentContract := callFrame.GetTo()

	// find interesting values
	from := callFrame.GetFrom()
	interestingValues[common.BytesToHash(from[:])] = append(interestingValues[common.BytesToHash(from[:])], &ArgValue{
		Value: from,
		Name:  "msg.sender",
	})
	interestingValues[common.BytesToHash(currentContract[:])] = append(interestingValues[common.BytesToHash(currentContract[:])], &ArgValue{
		Value: currentContract,
		Name:  "callee",
	})
	mergedStateVariables, _ := GetDynamicVariables(callFrame, interestingValues)
	for argName, argValue := range argValueMap {
		mergedStateVariables[argName] = &StateValue{
			Value: argValue.Value,
			Type:  argValue.Type,
		}
	}
	attachTransactionInfo(callFrame, mergedStateVariables)
	return mergedStateVariables
}

func attachTransactionInfo(callFrame *CallFrame, stateVariables map[string]*StateValue) {
	stateVariables["msg.sender"] = &StateValue{
		Value: callFrame.From,
		Type:  "address",
	}
	stateVariables["callee"] = &StateValue{
		Value: callFrame.To,
		Type:  "address",
	}
	stateVariables["msg.value"] = &StateValue{
		Value: callFrame.Value,
		Type:  "uint256",
	}
}
