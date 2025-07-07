package contracts

// import (
// 	"fmt"
// 	"math/big"
// 	"reflect"
// 	"strconv"

// 	"github.com/crytic/medusa/utils/reflectionutils"
// 	"github.com/ethereum/go-ethereum/accounts/abi"
// 	"github.com/ethereum/go-ethereum/common"
// )

// type ArgValue struct {
// 	Value any
// 	Type  string
// 	Name  string
// 	Base  byte
// }

// type CallFrame interface {
// 	GetTo() common.Address
// 	GetFrom() common.Address
// 	GetInput() []byte
// 	GetConstructorArgsData() []byte

// 	GetStorage(common.Address, string) (map[common.Hash]common.Hash, bool)
// 	GetStorageExtractor() *StorageExtractor
// 	GetCodeContractAbi() *abi.ABI
// 	IsContractCreation() bool
// }

// func GetMethodSig(callFrame CallFrame) string {
// 	var (
// 		methodName = "<unresolved method>"
// 		method     *abi.Method
// 		err        error
// 	)
// 	// Resolve our contract names, as well as our method and its name from the code contract.
// 	codeContractAbi := callFrame.GetCodeContractAbi()
// 	input := callFrame.GetInput()
// 	if codeContractAbi != nil {
// 		if callFrame.IsContractCreation() {
// 			methodName = "constructor"
// 			method = &codeContractAbi.Constructor
// 		} else {
// 			method, err = codeContractAbi.MethodById(input)
// 			if err == nil {
// 				methodName = method.Sig
// 			}
// 		}
// 	}
// 	return methodName
// }

// func TravelABIArgs(inputs abi.Arguments, values []any, interestingValues map[common.Hash][]*ArgValue) (map[string]ArgValue, error) {
// 	argValueMap := make(map[string]ArgValue)
// 	// preStr := "function."
// 	for i, input := range inputs {
// 		err := travelABIArg(&input.Type, values[i], input.Name, argValueMap, interestingValues)
// 		if err != nil {
// 			err = fmt.Errorf("ABI value argument could not be decoded from JSON: \n"+
// 				"name: %v, abi type: %v, value: %v error: %s",
// 				input.Name, input.Type, values[i], err)
// 			return nil, err
// 		}
// 	}
// 	return argValueMap, nil
// }

// func travelABIArg(inputType *abi.Type, value any, name string, argValueMap map[string]ArgValue, inteinterestingValues map[common.Hash][]*ArgValue) error {
// 	switch inputType.T {
// 	case abi.AddressTy:
// 		addr, ok := value.(common.Address)
// 		if !ok {
// 			return fmt.Errorf("could not encode address input as the value provided is not an address type")
// 		}
// 		argValue := ArgValue{
// 			Value: addr,
// 			Type:  "address",
// 			Name:  name,
// 		}
// 		argValueMap[name] = argValue
// 		inteinterestingValues[common.BytesToHash(addr[:])] = append(inteinterestingValues[common.BytesToHash(addr[:])], &argValue)
// 	case abi.UintTy:
// 		v, ok := value.(*big.Int)
// 		if !ok {
// 			return fmt.Errorf("could not encode uint%v input as the value provided is not of the correct type", inputType.Size)
// 		}
// 		argValue := ArgValue{
// 			Value: v,
// 			Type:  "uint",
// 			Name:  name,
// 		}
// 		argValueMap[name] = argValue
// 		inteinterestingValues[common.BigToHash(v)] = append(inteinterestingValues[common.BigToHash(v)], &argValue)
// 	case abi.IntTy:
// 		v, ok := value.(*big.Int)
// 		if !ok {
// 			return fmt.Errorf("could not encode uint%v input as the value provided is not of the correct type", inputType.Size)
// 		}
// 		argValue := ArgValue{
// 			Value: v,
// 			Type:  "int",
// 			Name:  name,
// 		}
// 		argValueMap[name] = argValue
// 		// inteinterestingValues[common.BigToHash(v)] = &argValue
// 		inteinterestingValues[common.BigToHash(v)] = append(inteinterestingValues[common.BigToHash(v)], &argValue)
// 	case abi.BoolTy:
// 		b, ok := value.(bool)
// 		if !ok {
// 			return fmt.Errorf("could not encode bool as the value provided is not of the correct type")
// 		}
// 		argValue := ArgValue{
// 			Value: b,
// 			Type:  "bool",
// 			Name:  name,
// 		}
// 		argValueMap[name] = argValue
// 		// inteinterestingValues[common.HexToHash(strconv.FormatBool(b))] = &argValue
// 		inteinterestingValues[common.HexToHash(strconv.FormatBool(b))] = append(inteinterestingValues[common.HexToHash(strconv.FormatBool(b))], &argValue)
// 	case abi.StringTy:
// 		str, ok := value.(string)
// 		if !ok {
// 			return fmt.Errorf("could not encode string as the value provided is not of the correct type")
// 		}
// 		argValue := ArgValue{
// 			Value: str,
// 			Type:  "string",
// 			Name:  name,
// 		}
// 		argValueMap[name] = argValue
// 		// inteinterestingValues[common.HexToHash(str)] = &argValue
// 		inteinterestingValues[common.HexToHash(str)] = append(inteinterestingValues[common.HexToHash(str)], &argValue)
// 	case abi.BytesTy:
// 		b, ok := value.([]byte)
// 		if !ok {
// 			return fmt.Errorf("could not encode dynamic-sized bytes as the value provided is not of the correct type")
// 		}
// 		argValue := ArgValue{
// 			Value: b,
// 			Type:  "bytes",
// 			Name:  name,
// 		}
// 		argValueMap[name] = argValue
// 		// inteinterestingValues[common.BytesToHash(b)] = &argValue
// 		inteinterestingValues[common.BytesToHash(b)] = append(inteinterestingValues[common.BytesToHash(b)], &argValue)
// 	case abi.FixedBytesTy:
// 		// TODO: Error checking to ensure `value` is of the correct type.
// 		b := reflectionutils.ArrayToSlice(reflect.ValueOf(value)).([]byte)
// 		argValue := ArgValue{
// 			Value: b,
// 			Type:  "fixedBytesTy",
// 			Name:  name,
// 		}
// 		argValueMap[name] = argValue
// 		// inteinterestingValues[common.BytesToHash(b)] = &argValue
// 		inteinterestingValues[common.BytesToHash(b)] = append(inteinterestingValues[common.BytesToHash(b)], &argValue)
// 	case abi.ArrayTy:
// 		// ignore the case of "[]struct"
// 		reflectedArray := reflect.ValueOf(value)
// 		for i := 0; i < reflectedArray.Len(); i++ {
// 			if inputType.Elem.T != abi.TupleTy && inputType.Elem.T != abi.ArrayTy && inputType.Elem.T != abi.SliceTy {
// 				argValue := ArgValue{
// 					Value: reflectedArray,
// 					Type:  "array",
// 					Name:  name,
// 					Base:  inputType.Elem.T,
// 				}
// 				argValueMap[name] = argValue
// 			}
// 			// err := travelABIArg(inputType.Elem, reflectedArray.Index(i).Interface(), name+fmt.Sprintf("[%v]", i), argValueMap, inteinterestingValues)
// 			// if err != nil {
// 			// 	return err
// 			// }
// 		}
// 	case abi.SliceTy:
// 		reflectedArray := reflect.ValueOf(value)
// 		if inputType.Elem.T != abi.TupleTy && inputType.Elem.T != abi.ArrayTy && inputType.Elem.T != abi.SliceTy {
// 			argValue := ArgValue{
// 				Value: reflectedArray,
// 				Type:  "array",
// 				Name:  name,
// 				Base:  inputType.Elem.T,
// 			}
// 			argValueMap[name] = argValue
// 		}
// 		// for i := 0; i < reflectedArray.Len(); i++ {
// 		// 	err := travelABIArg(inputType.Elem, reflectedArray.Index(i).Interface(), name+fmt.Sprintf("[%v]", i), argValueMap, inteinterestingValues)
// 		// 	if err != nil {
// 		// 		return err
// 		// 	}
// 		// }
// 	case abi.TupleTy:
// 		reflectedTuple := reflect.ValueOf(value)
// 		for i := 0; i < len(inputType.TupleElems); i++ {
// 			field := reflectedTuple.Field(i)
// 			fieldValue := reflectionutils.GetField(field)
// 			err := travelABIArg(inputType.TupleElems[i], fieldValue, name+"."+inputType.TupleRawNames[i], argValueMap, inteinterestingValues)
// 			if err != nil {
// 				return err
// 			}
// 		}
// 	default:
// 		return fmt.Errorf("could not encode argument as string, type is unsupported: %v", inputType)
// 	}
// 	return nil
// }
