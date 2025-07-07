package fuzzing

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/invariant"
	"github.com/crytic/medusa/utils/reflectionutils"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
)

type StateExtractor struct {
	worker             *FuzzerWorker
	viewMethodCache    map[string]*ViewMethodCacheItem // map[methodSig]*ViewMethodCacheItem
	stateVariablesType map[string]string

	// for sensitive variable
	slotToViewMethodMap map[string]map[string]any
	candidateViewMethod map[string]any
}

type ViewMethodCacheItem struct {
	id               string
	isConstant       bool
	sloadSlot        map[common.Address]map[common.Hash]common.Hash
	cacheStateValues []*invariant.StateValue
	returnData       []byte

	// for calling
	address common.Address
	data    []byte
	method  abi.Method
}

func (s *StateExtractor) initStateVariablesFromViewMethods() error {
	worker := s.worker
	for address := range worker.contractViewMethod {
		for _, method := range worker.contractViewMethod[address] {
			if len(method.Inputs) == 0 {
				data := method.ID
				addressMethodSig := fmt.Sprintf("%s-%s-%s", address.String(), method.Sig, hex.EncodeToString(data))
				_, err := s.getStateVariablesFromViewMethod(worker, address, data, method)
				if err != nil {
					continue
				}

				if !s.viewMethodCache[addressMethodSig].isConstant {
					// s.stateVariablesType[addressMethodSig] = "common"
					s.stateVariablesType[addressMethodSig] = "sensitive-candidate"
					s.candidateViewMethod[addressMethodSig] = nil

					for address := range s.viewMethodCache[addressMethodSig].sloadSlot {
						for slot := range s.viewMethodCache[addressMethodSig].sloadSlot[address] {
							id := fmt.Sprintf("%s-%s", strings.ToLower(address.String()), strings.ToLower(slot.String()))
							if _, ok1 := s.slotToViewMethodMap[id]; !ok1 {
								s.slotToViewMethodMap[id] = make(map[string]any)
							}
							s.slotToViewMethodMap[id][addressMethodSig] = nil
						}
					}
				}
			} else {
				// deal with sensitive variables
				if len(method.Inputs) == 1 && method.Inputs[0].Type.T == abi.AddressTy {
					var users = []common.Address{worker.fuzzer.senders[0], FuzzHelperContractAddr}
					for _, user := range users {
						// try sender
						data, err := method.Inputs.Pack(user)
						if err != nil {
							return fmt.Errorf("error in initStateVariablesFromViewMethods: %v", err)
						}
						data = append(method.ID, data...)
						_, err = s.getStateVariablesFromViewMethod(worker, address, data, method)
						if err != nil {
							continue
						}
						addressMethodSig := fmt.Sprintf("%s-%s-%s", address.String(), method.Sig, hex.EncodeToString(data))
						s.stateVariablesType[addressMethodSig] = "sensitive-candidate"
						s.candidateViewMethod[addressMethodSig] = nil

						for address := range s.viewMethodCache[addressMethodSig].sloadSlot {
							for slot := range s.viewMethodCache[addressMethodSig].sloadSlot[address] {
								id := fmt.Sprintf("%s-%s", strings.ToLower(address.String()), strings.ToLower(slot.String()))
								if _, ok1 := s.slotToViewMethodMap[id]; !ok1 {
									s.slotToViewMethodMap[id] = make(map[string]any)
								}
								s.slotToViewMethodMap[id][addressMethodSig] = nil
							}
						}
					}
				}
			}
		}
	}

	// deal with token variables
	var interestingAddresses []common.Address
	interestingAddresses = append(interestingAddresses, s.worker.fuzzer.senders[0])
	interestingAddresses = append(interestingAddresses, s.worker.fuzzer.targetContractAddresses...)
	for _, token := range s.worker.fuzzer.targetContractAddresses {
		for _, user := range interestingAddresses {
			data, err := ERC20Abi.Pack("balanceOf", user)
			if err != nil {
				return fmt.Errorf("failed to pack balanceOf: %v", err)
			}
			addressMethodSig := fmt.Sprintf("%s-%s-%s", token.String(), "balanceOf(address)", hex.EncodeToString(data))
			s.getStateVariablesFromViewMethod(worker, token, data, ERC20Abi.Methods["balanceOf"])

			if _, ok := s.viewMethodCache[addressMethodSig]; ok {
				// s.stateVariablesType[addressMethodSig] = "token"
				s.stateVariablesType[addressMethodSig] = "sensitive-candidate"
				s.candidateViewMethod[addressMethodSig] = nil

				for address := range s.viewMethodCache[addressMethodSig].sloadSlot {
					for slot := range s.viewMethodCache[addressMethodSig].sloadSlot[address] {
						id := fmt.Sprintf("%s-%s", strings.ToLower(address.String()), strings.ToLower(slot.String()))
						if _, ok1 := s.slotToViewMethodMap[id]; !ok1 {
							s.slotToViewMethodMap[id] = make(map[string]any)
						}
						s.slotToViewMethodMap[id][addressMethodSig] = nil
					}
				}
			} else {
				// panic(fmt.Sprintf("not existing token variable %s", addressMethodSig))
			}
		}
	}
	return nil
}

func isConsiderType(t string) bool {
	switch t {
	case "uint256":
		return true
	case "address":
		return true
	default:
		return false
	}
}

func (s *StateExtractor) getStateVariables(callSequenceElement *calls.CallSequenceElement) (map[string]*invariant.StateValue, error) {
	stateVariables := make(map[string]*invariant.StateValue)

	// obtain ether balance
	var users = []common.Address{s.worker.fuzzer.senders[0], FuzzHelperContractAddr}
	balance := big.NewInt(0)
	for _, user := range users {
		balance = new(big.Int).Add(balance, s.getEtherBalance(user))
	}
	stateVariables["ether-sender"] = &invariant.StateValue{
		Value:  balance,
		Type:   "uint256",
		Source: "sensitive",
	}

	// update sensitive variables
	if len(s.candidateViewMethod) > 0 {
		block := callSequenceElement.ChainReference.Block
		messageResult := block.MessageResults[callSequenceElement.ChainReference.TransactionIndex]
		stateTraceResult := messageResult.AdditionalResults[invariant.StateTraceResultKey].(invariant.StateTraceResult)
		if stateTraceResult.IsTransfer {
			for address := range stateTraceResult.SloadSlot {
				for slot := range stateTraceResult.SloadSlot[address] {
					id := fmt.Sprintf("%s-%s", strings.ToLower(address.String()), strings.ToLower(slot.String()))
					if _, ok := s.slotToViewMethodMap[id]; ok {
						for addressMethodSig := range s.slotToViewMethodMap[id] {
							if _, ok1 := s.candidateViewMethod[addressMethodSig]; ok1 {
								s.stateVariablesType[addressMethodSig] = "sensitive"
								delete(s.candidateViewMethod, addressMethodSig)
							}
						}
					}
				}
			}
		}

	} else {
		// s.worker.stateTracer = &invariant.StateTracer{}
	}

	for name, t := range s.stateVariablesType {
		if viewMethodCacheItem, ok := s.viewMethodCache[name]; ok {
			if t == "common" {
				stateValues, err := s.getStateVariablesFromViewMethod(s.worker, viewMethodCacheItem.address, viewMethodCacheItem.data, viewMethodCacheItem.method)
				if err != nil {
				}
				for index, stateValue := range stateValues {
					if stateValue != nil && isConsiderType(stateValue.Type) {
						stateValue.Source = t
						stateValueName := fmt.Sprintf("%s-%d", name, index)
						stateVariables[stateValueName] = stateValue
					}
				}
			} else if t == "sensitive" || t == "token" {
				stateValues, err := s.getStateVariablesFromViewMethod(s.worker, viewMethodCacheItem.address, viewMethodCacheItem.data, viewMethodCacheItem.method)
				if err != nil {
				}
				for index, stateValue := range stateValues {
					if stateValue != nil {
						stateValue.Source = t
						stateValueName := fmt.Sprintf("%s-%d", name, index)
						stateVariables[stateValueName] = stateValue
					}
				}
			} else {
				// fmt.Println(s.viewMethodCache[name])
			}
		}
	}

	return stateVariables, nil
}

func (s *StateExtractor) getStateVariablesFromViewMethosWithVariables(stateVariableMethod map[string]any) (map[string]*invariant.StateValue, error) {
	stateVariables := make(map[string]*invariant.StateValue)
	for name := range stateVariableMethod {
		if viewMethodCacheItem, ok := s.viewMethodCache[name]; ok {
			stateValues, err := s.getStateVariablesFromViewMethod(s.worker, viewMethodCacheItem.address, viewMethodCacheItem.data, viewMethodCacheItem.method)
			if err != nil {
				return nil, err
			}
			for index, stateValue := range stateValues {
				if stateValue != nil {
					stateValueName := fmt.Sprintf("%s-%d", name, index)
					stateVariables[stateValueName] = stateValue
				}
			}
		} else {
			panic(fmt.Sprintf("getStateVariablesFromViewMethosWithVariables not existing viewMethodCacheItem %s", name))
		}
	}
	return stateVariables, nil
}

func (s *StateExtractor) isStoredVariable() bool {
	return false
}

func (s *StateExtractor) getStateVariablesFromViewMethod(worker *FuzzerWorker, address common.Address, data []byte, method abi.Method) ([]*invariant.StateValue, error) {
	var isRequiredCall bool
	addressMethodSig := fmt.Sprintf("%s-%s-%s", address.String(), method.Sig, hex.EncodeToString(data))

	// cache
	if viewMethodCacheItem, ok := s.viewMethodCache[addressMethodSig]; ok {
		for address := range viewMethodCacheItem.sloadSlot {
			for slot, value := range viewMethodCacheItem.sloadSlot[address] {
				var newValue common.Hash
				if worker.chain.IsOnChain {
					newValue = worker.chain.CacheAccountState.TraceAccountState.GetStorage(address, slot)
				} else {
					newValue = worker.chain.State().GetState(address, slot)
				}
				if value != newValue {
					isRequiredCall = true
					break
				}
			}
			if isRequiredCall {
				break
			}
		}
	} else {
		isRequiredCall = true
	}

	if isRequiredCall {
		var err error
		msg := calls.NewCallMessage(checkerAddress, &address, 0, big.NewInt(0), worker.fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, data)
		msg.FillFromTestChainProperties(worker.chain)
		stateTracer := &invariant.StateTracer{
			RecordingSLOAD: true,
		}
		var executionResult *core.ExecutionResult
		if worker.chain.IsOnChain {
			// executionTracer := executiontracer.NewExecutionTracer(worker.fuzzer.contractDefinitions, worker.Chain().CheatCodeContracts())
			executionResult, err = worker.Chain().CallContractOnChain(msg.ToCoreMessage(), nil, stateTracer)
			// fmt.Print(executionTracer.Trace().Log())
		} else {
			executionResult, err = worker.Chain().CallContract(msg.ToCoreMessage(), nil, stateTracer)
		}
		if err != nil {
			return nil, err
		}

		if executionResult.Err != nil {
			return nil, executionResult.Err
		}

		retVals, err := method.Outputs.Unpack(executionResult.ReturnData)
		if err != nil {
			return nil, err
		}

		newSloadSlot := stateTracer.SloadSlot

		// for util variables
		if _, ok := s.viewMethodCache[addressMethodSig]; !ok {
			s.viewMethodCache[addressMethodSig] = &ViewMethodCacheItem{
				address: address,
				data:    data,
				method:  method,
			}
		}

		s.viewMethodCache[addressMethodSig].sloadSlot = newSloadSlot
		s.viewMethodCache[addressMethodSig].isConstant = len(newSloadSlot) == 0
		s.viewMethodCache[addressMethodSig].returnData = executionResult.ReturnData
		s.viewMethodCache[addressMethodSig].cacheStateValues = []*invariant.StateValue{}
		for index, output := range method.Outputs {
			newStateValue := getStateValue(output, retVals[index])
			s.viewMethodCache[addressMethodSig].cacheStateValues = append(s.viewMethodCache[addressMethodSig].cacheStateValues, newStateValue)
		}
	}
	return s.viewMethodCache[addressMethodSig].cacheStateValues, nil
}

func getIntStateValue(arg abi.Argument, retVal interface{}) *big.Int {
	switch retVal.(type) {
	case *big.Int:
		return retVal.(*big.Int)
	case uint8:
		return big.NewInt(int64(retVal.(uint8)))
	case uint16:
		return big.NewInt(int64(retVal.(uint16)))
	case uint32:
		return big.NewInt(int64(retVal.(uint32)))
	case uint64:
		return big.NewInt(int64(retVal.(uint64)))
	// case uint256:
	// 	return big.NewInt(int64(retVal.(uint256)))
	case int8:
		return big.NewInt(int64(retVal.(int8)))
	case int16:
		return big.NewInt(int64(retVal.(int16)))
	case int32:
		return big.NewInt(int64(retVal.(int32)))
	default:
		fmt.Println(arg.Type.GetType(), retVal, arg)
		panic("unknown type")
	}
}

func getStateValue(arg abi.Argument, retVal interface{}) *invariant.StateValue {
	switch arg.Type.T {
	case abi.IntTy:
		val := getIntStateValue(arg, retVal)
		return &invariant.StateValue{
			Value: val,
			Type:  "uint256",
		}
	case abi.UintTy:
		val := getIntStateValue(arg, retVal)
		return &invariant.StateValue{
			Value: val,
			Type:  "uint256",
		}
	case abi.BoolTy:
		return &invariant.StateValue{
			Value: retVal.(bool),
			Type:  "bool",
		}
	case abi.StringTy:
		// return &invariant.StateValue{
		// 	Value: retVal.(string),
		// 	Type:  "string",
		// }
		return nil
	case abi.SliceTy:
		// fmt.Println("abi.SliceTy")
	case abi.ArrayTy:
		fmt.Println("abi.ArrayTy")
	case abi.TupleTy:
		fmt.Println("tuple")
	case abi.AddressTy:
		return &invariant.StateValue{
			Value: retVal.(common.Address),
			Type:  "address",
		}
	case abi.FixedBytesTy:
		b := reflectionutils.ArrayToSlice(reflect.ValueOf(retVal)).([]byte)
		return &invariant.StateValue{
			Value: b,
			Type:  "fixedBytesTy",
		}
	case abi.BytesTy:
		b, ok := retVal.([]byte)
		if !ok {
			panic("could not encode dynamic-sized bytes as the value provided is not of the correct type")
		}
		return &invariant.StateValue{
			Value: b,
			Type:  "bytes",
		}
	case abi.HashTy:
		return &invariant.StateValue{
			Value: retVal.(common.Hash),
			Type:  "hash",
		}
	case abi.FixedPointTy:
		fmt.Println("abi.FixedPointTy")
	case abi.FunctionTy:
		fmt.Println("abi.FunctionTy")
	default:
		panic("Invalid type")
	}
	return nil
}

func getArgumentFromString(arg abi.Argument, value string) interface{} {
	switch arg.Type.T {
	case abi.IntTy:
		v, flag := new(big.Int).SetString(value, 10)
		if !flag {
			panic("error in setString in getArgumentFromString")
		}
		return v
	case abi.UintTy:
		v, flag := new(big.Int).SetString(value, 10)
		if !flag {
			panic("error in setString in getArgumentFromString")
		}
		return v
	case abi.BoolTy:
		if value == "true" {
			return true
		} else {
			return false
		}
	case abi.AddressTy:
		return common.HexToAddress(value)
	default:
		fmt.Println(arg.Type.GetType())
		panic("not support type in getArgumentFromString")
	}
}

func (worker *FuzzerWorker) stateVariablesChecker(oldStateVariables, newStateVariables map[string]*invariant.StateValue) map[string][]*invariant.StateValue {
	violatedVariable := make(map[string][]*invariant.StateValue)
	// satisfaction := true
	for name, value0 := range oldStateVariables {
		if value1, ok := newStateVariables[name]; ok {
			if value0.Cmp(value1) != 0 {
				// satisfaction = false
				violatedVariable[name] = []*invariant.StateValue{value0, value1}
				// fmt.Println(name, value0, value1)
			}
		}
	}

	return violatedVariable
}

func (worker *FuzzerWorker) updateSeedPool(stateVariables map[string]*invariant.StateValue) error {
	for _, item := range stateVariables {
		if item.Type == "uint256" {
			worker.valueSet.AddInteger(item.Value.(*big.Int))
		} else if item.Type == "address" {
			worker.valueSet.AddAddress(item.Value.(common.Address))
		}
	}
	return nil
}

func (worker *FuzzerWorker) getStateVariables(callSequence calls.CallSequence) (map[string]*invariant.StateValue, error) {
	// if the transaction reverts, continue
	callSequenceElement := callSequence[len(callSequence)-1]
	block := callSequenceElement.ChainReference.Block
	messageResult := block.MessageResults[callSequenceElement.ChainReference.TransactionIndex]
	if messageResult.ExecutionResult.Err != nil {
		return nil, nil
	}

	stateVariables, err := worker.stateExtractor.getStateVariables(callSequenceElement)
	if err != nil {
		return nil, err
	}

	return stateVariables, nil
}

func (worker *FuzzerWorker) genShrinkRequestWithStateVariables(callSequence calls.CallSequence) ([]ShrinkCallSequenceRequest, error) {
	shrinkRequests := make([]ShrinkCallSequenceRequest, 0)

	// if the transaction reverts, continue
	callSequenceElement := callSequence[len(callSequence)-1]
	block := callSequenceElement.ChainReference.Block
	messageResult := block.MessageResults[callSequenceElement.ChainReference.TransactionIndex]
	if messageResult.ExecutionResult.Err != nil {
		return shrinkRequests, nil
	}

	stateVariables, err := worker.stateExtractor.getStateVariables(callSequenceElement)
	if err != nil {
		return nil, err
	}

	// add interesting value to seed pool
	worker.updateSeedPool(stateVariables)

	isNewStateValue, err := worker.fuzzer.corpus.CheckSequenceScopeInvariantAndUpdate(callSequence, worker.getNewCorpusCallSequenceWeight(), true, worker.fuzzer.config.Fuzzing.UseStateGuided(), stateVariables)
	if err != nil {
		return nil, err
	}

	// for tracing slots
	var isNewSlotValue bool
	// if worker.fuzzer.config.Fuzzing.UseSlotTracing() {
	// 	isNewSlotValue, err = worker.fuzzer.corpus.CheckSequenceSlotsAndUpdate(callSequence, worker.getNewCorpusCallSequenceWeight(), true)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	var isNewScope bool
	if worker.fuzzer.config.Fuzzing.StateGuidedConfig.EnabledStateGuided {
		if !worker.fuzzer.config.Fuzzing.StateGuidedConfig.EnabledStateConstruction {
			isNewScope = isNewSlotValue
		} else {
			isNewScope = isNewStateValue
		}
	}

	if isNewScope {
		stateVariableMethod := make(map[string]any)
		for name := range stateVariables {
			strList := strings.Split(name, "-")
			addressMethodSig := strings.Join(strList[:len(strList)-1], "-")
			stateVariableMethod[addressMethodSig] = nil
		}
		if !worker.fuzzer.config.Fuzzing.StateGuidedConfig.EnabledCompression {
			err = worker.fuzzer.corpus.AddSequence(callSequence, worker.getNewCorpusCallSequenceWeight(), true)
			if err != nil {
				return shrinkRequests, fmt.Errorf("error in AddSequence: %v", err)
			}
		} else {
			shrinkRequest := ShrinkCallSequenceRequest{
				VerifierFunction: func(worker *FuzzerWorker, shrunkenCallSequence calls.CallSequence) (bool, error) {
					// shrink verifier simply ensures the previously failed property test fails
					// for the shrunk sequence as well.
					existViolatedVariable := false
					newStateVariables, err := worker.stateExtractor.getStateVariablesFromViewMethosWithVariables(stateVariableMethod)
					if err != nil {
						return false, err
					}
					violatedVariables := worker.stateVariablesChecker(stateVariables, newStateVariables)
					existViolatedVariable = len(violatedVariables) > 0
					return !existViolatedVariable, err
				},
				FinishedCallback: func(worker *FuzzerWorker, shrunkenCallSequence calls.CallSequence) error {
					var err error
					newStateVariables, err := worker.stateExtractor.getStateVariablesFromViewMethosWithVariables(stateVariableMethod)
					if err != nil {
						return err
					}

					// Execute the property test a final time, this time obtaining an execution trace
					violatedVariables := worker.stateVariablesChecker(stateVariables, newStateVariables)
					existViolatedVariable := len(violatedVariables) > 0

					// ignore the case that shrunkenSequenceSatisfaction = false
					if existViolatedVariable {
						return fmt.Errorf("invariant checker did not satisfy the stateVariables on final shrunken sequence")
					}

					// for update corpus
					err = worker.fuzzer.corpus.AddSequence(shrunkenCallSequence, worker.getNewCorpusCallSequenceWeight(), true)
					if err != nil {
						return fmt.Errorf("error in AddSequence: %v", err)
					}
					return nil
				},
			}
			shrinkRequests = append(shrinkRequests, shrinkRequest)
		}
	}

	return shrinkRequests, nil
}

func (s *StateExtractor) getOriBalance(worker *FuzzerWorker) *invariant.StateValue {
	// var users = []common.Address{worker.fuzzer.senders[0], FuzzHelperContractAddr}
	// oriBalance := big.NewInt(0)
	// deal with ether
	// for _, user := range users {
	// oriBalance = new(big.Int).Add(oriBalance, worker.Chain().CacheAccountState.InitAccountState.GetBalance(user))
	// }
	// oriBalance, _ := new(big.Int).SetString("100000000000000000000", 10)
	oriBalance := new(big.Int).Set(worker.fuzzer.config.Fuzzing.SenderAddressesBalances[0])

	return &invariant.StateValue{
		Value: oriBalance,
		Type:  "uint256",
	}
}

func (s *StateExtractor) getEtherBalance(address common.Address) *big.Int {
	return s.worker.Chain().State().GetBalance(address)
}

func (s *StateExtractor) getBalance() (*invariant.StateValue, []*big.Int, map[common.Address]*big.Int) {
	var err error
	var users = []common.Address{s.worker.fuzzer.senders[0], FuzzHelperContractAddr}
	var valueSet []*big.Int
	postBalance := big.NewInt(0)
	tokenBalanceMap := make(map[common.Address]*big.Int)

	// deal with ether
	for _, user := range users {
		postBalance = new(big.Int).Add(postBalance, s.getEtherBalance(user))
		valueSet = append(valueSet, new(big.Int).Set(s.getEtherBalance(user)))
	}
	tokenBalanceMap[common.HexToAddress("0x")] = new(big.Int).Set(postBalance)

	for _, token := range s.worker.fuzzer.targetContractAddresses {
		tokenBalanceMap[token] = big.NewInt(0)
		for _, user := range users {
			var balance *big.Int
			// balance, err = GetTokenBalance(worker, user, token)
			balance, err = s.getTokenBalance(s.worker, user, token)
			if err != nil {
				continue
			}
			tokenBalanceMap[token] = new(big.Int).Add(tokenBalanceMap[token], balance)
			valueSet = append(valueSet, new(big.Int).Set(balance))
		}
	}

	// swap other tokens to ether
	for token, balance := range tokenBalanceMap {
		if token == common.HexToAddress("0x") {
			continue
		}
		if balance.Cmp(big.NewInt(0)) == 1 {
			// try uniswapV2
			swapToEthBalance, err := swapTokenWithUniswapV2(s.worker, checkerAddress, token, balance)
			if err != nil {
				if swapToEthBalance.Cmp(big.NewInt(0)) == 0 {
					// try uniswapV1
					swapToEthBalance, err = swapTokenWithUniswapV1(s.worker, checkerAddress, token, balance)
					if err != nil {
						continue
					}
				}
			}
			postBalance = new(big.Int).Add(postBalance, swapToEthBalance)
		}
	}
	return &invariant.StateValue{Value: new(big.Int).Set(postBalance), Type: "uint256"}, valueSet, tokenBalanceMap
}

// balanceOf(sender)
func (s *StateExtractor) getTokenBalance(worker *FuzzerWorker, addr, token common.Address) (*big.Int, error) {
	var err error

	data, err := ERC20Abi.Pack("balanceOf", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to pack balanceOf: %v", err)
	}
	retVals, err := s.getStateVariablesFromViewMethod(worker, token, data, ERC20Abi.Methods["balanceOf"])
	if err != nil {
		return nil, err
	}
	return retVals[0].Value.(*big.Int), nil
}
