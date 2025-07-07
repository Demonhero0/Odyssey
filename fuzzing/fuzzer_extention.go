package fuzzing

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/fuzzing/calls"
	fuzzingTypes "github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/valuegeneration"
	"github.com/crytic/medusa/logging"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
)

var uniswapV2Contract *fuzzingTypes.Contract
var uniswapV1Contract *fuzzingTypes.Contract
var ERC1820RegistryContract *fuzzingTypes.Contract
var FuzzHelperContract *fuzzingTypes.Contract
var utilAddressMap map[common.Address]UtilAddress
var TokenHelper []byte
var TokenHelperAbi abi.ABI
var ERC20Contract *fuzzingTypes.Contract
var ERC20Abi abi.ABI

type UtilAddress struct {
	Balance *big.Int
	Code    []byte
}

func init() {
	var err error
	// init uniswapV2
	uniswapV2ABI, err := abi.JSON(strings.NewReader(UniswapV2RouterABIString))
	if err != nil {
		fmt.Println("Parser error", err)
	}

	uniswapV2Contract = fuzzingTypes.NewContract("UniswapV2Router", "", &types.CompiledContract{
		Abi: uniswapV2ABI,
	}, nil)

	// init uniswapV1
	uniswapV1ABI, err := abi.JSON(strings.NewReader(UniswapV1AbiString))
	if err != nil {
		fmt.Println("Parser error", err)
	}

	uniswapV1Contract = fuzzingTypes.NewContract("UniswapV1", "", &types.CompiledContract{
		Abi: uniswapV1ABI,
	}, nil)

	// init ERC1820Registry
	ERC1820ABI, err := abi.JSON(strings.NewReader(ERC1820RegistryAbiString))
	if err != nil {
		fmt.Println("Parser error", err)
	}

	ERC1820RegistryBytecode, _ := hex.DecodeString(ERC1820RegistryBytecodeStr)
	ERC1820RegistryContract = fuzzingTypes.NewContract("ERC1820Registry", "", &types.CompiledContract{
		Abi:             ERC1820ABI,
		RuntimeBytecode: ERC1820RegistryBytecode,
	}, nil)

	// init FuzzHelperContract
	fuzzHelperAbi, err := abi.JSON(strings.NewReader(FuzzHelperContractAbiString))
	if err != nil {
		fmt.Println("Parser error", err)
	}

	fuzzHelperBytecode, _ := hex.DecodeString(FuzzHelperContractBytecode)
	fuzzHelperDeployedBytecode, _ := hex.DecodeString(FuzzHelperContractDeployedBytecode)
	FuzzHelperContract = fuzzingTypes.NewContract("FuzzHelperContract", "", &types.CompiledContract{
		Abi:             fuzzHelperAbi,
		InitBytecode:    fuzzHelperBytecode,
		RuntimeBytecode: fuzzHelperDeployedBytecode,
	}, nil)

	TokenHelper, _ = hex.DecodeString(TokenHelperContractDeployedBytecode)
	TokenHelperAbi, err = abi.JSON(strings.NewReader(TokenHelperABIString))
	if err != nil {
		fmt.Println("Parser error", err)
	}

	utilAddressMap = make(map[common.Address]UtilAddress)
	utilAddressMap[checkerAddress] = UtilAddress{
		Balance: math.MaxBig256,
		Code:    []byte{},
	}
	// utilAddressMap[InternalCallHelperAddress] = UtilAddress{
	// 	Balance: big.NewInt(0),
	// 	Code:    []byte{},
	// }
	utilAddressMap[TokenHelperAddress] = UtilAddress{
		Balance: big.NewInt(0),
		Code:    TokenHelper,
	}

	ERC20Abi, err = abi.JSON(strings.NewReader(ERC20ABIString))
	if err != nil {
		fmt.Println("Parser error", err)
	}
	ERC20Contract = fuzzingTypes.NewContract("ERC20", "ERC20", &types.CompiledContract{
		Abi: ERC20Abi,
	}, nil)
}

func (fuzzer *Fuzzer) checkIsExistUniswapV2Pair(testChain *chain.TestChain, token0, token1 common.Address) (bool, error) {
	data, err := uniswapV2Contract.CompiledContract().Abi.Pack("getPair", token0, token1)
	if err != nil {
		return false, fmt.Errorf("failed to pack getPair: %v", err)
	}
	contract := uniswapV2FactoryAddr
	checkMsg := calls.NewCallMessage(checkerAddress, &contract, 0, big.NewInt(0), fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, data)
	checkMsg.FillFromTestChainProperties(testChain)
	executionResult, _ := testChain.CallContractOnChain(checkMsg.ToCoreMessage(), nil)
	if executionResult.Err == nil {
		pairAddress := common.HexToAddress("0x")
		if len(executionResult.ReturnData) > 0 {
			retVals, err := uniswapV2Contract.CompiledContract().Abi.Unpack("getPair", executionResult.ReturnData)
			if err != nil {
				return false, fmt.Errorf("failed to decode getPair: %v", err)
			}
			pairAddress = retVals[0].(common.Address)
			// fmt.Println(retVals[0].(common.Address), retVals[0].(common.Address) != common.HexToAddress("0x"))
		}
		return pairAddress != common.HexToAddress("0x"), nil
	} else {
		return false, fmt.Errorf("failed to execute swap: %v", executionResult.Err)
	}
}

func (fuzzer *Fuzzer) getUniswapV1Pair(testChain *chain.TestChain, token common.Address) (common.Address, error) {
	data, err := uniswapV1Contract.CompiledContract().Abi.Pack("getExchange", token)
	if err != nil {
		return common.HexToAddress("0x"), fmt.Errorf("failed to pack getExchange: %v", err)
	}
	contract := uniswapV1FactoryAddr
	checkMsg := calls.NewCallMessage(checkerAddress, &contract, 0, big.NewInt(0), fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, data)
	checkMsg.FillFromTestChainProperties(testChain)
	executionResult, _ := testChain.CallContractOnChain(checkMsg.ToCoreMessage(), nil)
	if executionResult.Err == nil {
		pairAddress := common.HexToAddress("0x")
		if len(executionResult.ReturnData) > 0 {
			retVals, err := uniswapV1Contract.CompiledContract().Abi.Unpack("getExchange", executionResult.ReturnData)
			if err != nil {
				return common.HexToAddress("0x"), fmt.Errorf("failed to decode getExchange: %v", err)
			}
			pairAddress = retVals[0].(common.Address)
		}
		return pairAddress, nil
	} else {
		return common.HexToAddress("0x"), fmt.Errorf("failed to execute swap: %v", executionResult.Err)
	}
}

func (fuzzer *Fuzzer) genApproveCallSequenceElement(testChain *chain.TestChain, owner, spender, token common.Address, contract *fuzzingTypes.Contract) *calls.CallSequenceElement {

	method := contract.CompiledContract().Abi.Methods["approve"]
	abiValueData := calls.CallMessageDataAbiValues{
		Method:      &method,
		InputValues: []any{spender, abi.MaxUint256},
	}
	msg := calls.NewCallMessageWithAbiValueData(owner, &token, 0, big.NewInt(0), fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, &abiValueData)
	msg.FillFromTestChainProperties(testChain)
	element := calls.NewCallSequenceElement(contract, msg, 0, 0)
	return element
}

func (fuzzer *Fuzzer) genTransferCallSequenceElement(testChain *chain.TestChain, sender, receiver, token common.Address, amount *big.Int, contract *fuzzingTypes.Contract) *calls.CallSequenceElement {
	method := contract.CompiledContract().Abi.Methods["transfer"]
	abiValueData := calls.CallMessageDataAbiValues{
		Method:      &method,
		InputValues: []any{receiver, amount},
	}
	msg := calls.NewCallMessageWithAbiValueData(sender, &token, 0, big.NewInt(0), fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, &abiValueData)
	msg.FillFromTestChainProperties(testChain)
	element := calls.NewCallSequenceElement(contract, msg, 0, 0)
	return element
}

func (fuzzer *Fuzzer) genERC1820RegistryCallSequenceElement(testChain *chain.TestChain, sender, _addr, _implementer common.Address, _interface, _methodStr string) *calls.CallSequenceElement {
	contract := ERC1820RegistryContract
	method, isExistMethod := contract.CompiledContract().Abi.Methods[_methodStr]
	if !isExistMethod {
		return nil
	}
	_interfaceHash, _ := hex.DecodeString(_interface)
	contractAddr := ERC1820RegistryAddr
	var abiValueData calls.CallMessageDataAbiValues
	// _interfaceHash := crypto.Keccak256Hash(_interface)
	switch _methodStr {
	case "setInterfaceImplementer":
		abiValueData = calls.CallMessageDataAbiValues{
			Method:      &method,
			InputValues: []any{_addr, common.BytesToHash(_interfaceHash), _implementer},
		}
	case "getInterfaceImplementer":
		abiValueData = calls.CallMessageDataAbiValues{
			Method:      &method,
			InputValues: []any{_addr, common.BytesToHash(_interfaceHash)},
		}
	default:
		return nil
	}
	msg := calls.NewCallMessageWithAbiValueData(sender, &contractAddr, 0, big.NewInt(0), fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, &abiValueData)
	msg.FillFromTestChainProperties(testChain)
	element := calls.NewCallSequenceElement(contract, msg, 0, 0)
	return element
}

func (fuzzer *Fuzzer) genUniswapV1SwapCallSequenceElement(testChain *chain.TestChain, amount *big.Int, token, sender, pairAddress common.Address) *calls.CallSequenceElement {
	method := uniswapV1Contract.CompiledContract().Abi.Methods["ethToTokenSwapInput"]
	abiValueData := calls.CallMessageDataAbiValues{
		Method:      &method,
		InputValues: []any{big.NewInt(1), big.NewInt(2722170808)},
	}
	contract := pairAddress
	msg := calls.NewCallMessageWithAbiValueData(sender, &contract, 0, amount, fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, &abiValueData)
	msg.FillFromTestChainProperties(testChain)

	element := calls.NewCallSequenceElement(uniswapV1Contract, msg, 0, 0)
	return element
}

func (fuzzer *Fuzzer) genUniswapV2SwapCallSequenceElement(testChain *chain.TestChain, amount *big.Int, token, sender, receiver common.Address) *calls.CallSequenceElement {
	var path = []common.Address{wethAddr, token}
	method := uniswapV2Contract.CompiledContract().Abi.Methods["swapExactETHForTokens"]
	abiValueData := calls.CallMessageDataAbiValues{
		Method:      &method,
		InputValues: []any{big.NewInt(0), path, receiver, big.NewInt(1722170808)},
	}
	contract := uniswapV2RouterAddr
	msg := calls.NewCallMessageWithAbiValueData(sender, &contract, 0, amount, fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, &abiValueData)
	msg.FillFromTestChainProperties(testChain)

	element := calls.NewCallSequenceElement(uniswapV2Contract, msg, 0, 0)
	element.UnableSendWithHelperContract = true
	return element
}

// balanceOf(sender)
func (worker *FuzzerWorker) GetTokenBalance(addr, token common.Address) (*big.Int, error) {
	data, _ := ERC20Abi.Pack("balanceOf", addr)
	msg := calls.NewCallMessage(checkerAddress, &token, 0, big.NewInt(0), worker.fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, data)
	msg.FillFromTestChainProperties(worker.chain)
	executionResult, err := worker.Chain().CallContractOnChain(msg.ToCoreMessage(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to check balance method: %v", err)
	}
	retVals, err := ERC20Abi.Unpack("balanceOf", executionResult.ReturnData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode balanceOf: %v", err)
	}
	// fmt.Println(token, retVals[0].(*big.Int))
	return retVals[0].(*big.Int), nil
}

// balanceOf(sender)
func GetTokenBalance(worker *FuzzerWorker, addr, token common.Address) (*big.Int, error) {
	data, _ := ERC20Abi.Pack("balanceOf", addr)
	msg := calls.NewCallMessage(checkerAddress, &token, 0, big.NewInt(0), worker.fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, data)
	msg.FillFromTestChainProperties(worker.chain)
	executionResult, err := worker.Chain().CallContractOnChain(msg.ToCoreMessage(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to check balance method: %v", err)
	}
	retVals, err := ERC20Abi.Unpack("balanceOf", executionResult.ReturnData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode balanceOf: %v", err)
	}
	// fmt.Println(token, retVals[0].(*big.Int))
	return retVals[0].(*big.Int), nil
}

// swap token to weth/eth
func swapTokenWithUniswapV2(worker *FuzzerWorker, sender, token common.Address, balance *big.Int) (*big.Int, error) {
	if token == wethAddr {
		return balance, nil
	} else {
		tokenBalance := big.NewInt(0)
		data, err := TokenHelperAbi.Pack("swapExactTokensForETHWithUniswapV2", token, balance)
		if err != nil {
			return tokenBalance, fmt.Errorf("failed to pack swapExactTokensForETHWithUniswapV2: %v", err)
		}
		helperAddr := TokenHelperAddress
		swapMsg := calls.NewCallMessage(sender, &helperAddr, 0, big.NewInt(0), worker.fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, data)
		swapMsg.FillFromTestChainProperties(worker.chain)
		// executionTracer := executiontracer.NewExecutionTracer(worker.fuzzer.contractDefinitions, worker.chain.CheatCodeContracts())
		executionResult, _ := worker.Chain().CallContractOnChain(swapMsg.ToCoreMessage(), nil)
		if executionResult.Err == nil {
			retVals, err := TokenHelperAbi.Unpack("swapExactTokensForETHWithUniswapV2", executionResult.ReturnData)
			if err != nil {
				return tokenBalance, fmt.Errorf("failed to decode swapExactTokensForETHWithUniswapV2: %v", err)
			}
			// fmt.Println(token, retVals[0].(*big.Int))
			return retVals[0].(*big.Int), nil
		} else {
			return tokenBalance, fmt.Errorf("failed to execute swap: %v", executionResult.Err)
		}
	}
}

// swap token to weth/eth
func swapTokenWithUniswapV1(worker *FuzzerWorker, sender, token common.Address, balance *big.Int) (*big.Int, error) {
	tokenBalance := big.NewInt(0)
	data, err := TokenHelperAbi.Pack("swapExactTokensForETHWithUniswapV1", token, balance)
	if err != nil {
		return tokenBalance, fmt.Errorf("failed to pack swapExactTokensForETHWithUniswapV1: %v", err)
	}
	helperAddr := TokenHelperAddress
	swapMsg := calls.NewCallMessage(sender, &helperAddr, 0, big.NewInt(0), worker.fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, data)
	swapMsg.FillFromTestChainProperties(worker.chain)
	// executionTracer := executiontracer.NewExecutionTracer(worker.fuzzer.contractDefinitions, worker.chain.CheatCodeContracts())
	executionResult, _ := worker.Chain().CallContractOnChain(swapMsg.ToCoreMessage(), nil)
	if executionResult.Err == nil {
		retVals, err := TokenHelperAbi.Unpack("swapExactTokensForETHWithUniswapV1", executionResult.ReturnData)
		if err != nil {
			return tokenBalance, fmt.Errorf("failed to decode swapExactTokensForETHWithUniswapV1: %v", err)
		}
		// fmt.Println(token, retVals[0].(*big.Int))
		return retVals[0].(*big.Int), nil
	} else {
		return tokenBalance, fmt.Errorf("failed to execute swap: %v", executionResult.Err)
	}
}

var reservedFunc = map[string]any{
	"e2dbeef4": nil, // sendMsgUtil(address,bytes)
	"7e5465ba": nil, // approve(address,address)
	"8da5cb5b": nil, // owner()
	"6017223f": nil, // swapTokens(address[])
}

type InternalCallHook struct {
	g                   *CallSequenceGenerator
	probability         float32
	helperAddress       common.Address
	callSequenceElement *calls.CallSequenceElement
}

func NewInternalCallHook(probability float32, generator *CallSequenceGenerator, callSequenceElement *calls.CallSequenceElement) *InternalCallHook {
	return &InternalCallHook{
		g:                   generator,
		helperAddress:       FuzzHelperContractAddr,
		probability:         probability,
		callSequenceElement: callSequenceElement,
	}
}

func (ichook *InternalCallHook) IsInternalCall(txOrigin, callee common.Address, depth int, input []byte) bool {
	if callee == ichook.helperAddress {
		if len(input) >= 4 {
			if _, ok := reservedFunc[hex.EncodeToString(input[:4])]; ok {
				return false
			}
		}
		if ichook.g.worker.randomProvider.Float32() > ichook.probability && ichook.callSequenceElement.InternalCall == nil {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

// internal contract call hook
func (ichook *InternalCallHook) InternalCallHandler(callee common.Address, depth int) (common.Address, []byte, *big.Int) {

	// Select a random method and sender
	selectedMethod := &ichook.g.worker.stateChangingMethods[ichook.g.worker.randomProvider.Intn(len(ichook.g.worker.stateChangingMethods))]
	// Generate fuzzed parameters for the function call
	args := make([]any, len(selectedMethod.Method.Inputs))
	for i := 0; i < len(args); i++ {
		// Create our fuzzed parameters.
		input := selectedMethod.Method.Inputs[i]
		args[i] = valuegeneration.GenerateAbiValue(ichook.g.config.ValueGenerator, &input.Type)
	}

	abiData := calls.CallMessageDataAbiValues{
		Method:      &selectedMethod.Method,
		InputValues: args,
	}

	// If this is a payable function, generate value to send
	var value *big.Int
	value = big.NewInt(0)
	balance := ichook.g.worker.Chain().State().GetBalance(FuzzHelperContractAddr)
	if selectedMethod.Method.StateMutability == "payable" && balance.Cmp(big.NewInt(0)) > 0 {
		value = ichook.g.config.ValueGenerator.GenerateInteger(false, 64)
		value = new(big.Int).Mod(value, balance)
	}

	// Pack the ABI value data
	var data []byte
	var err error
	data, err = abiData.Pack()
	if err != nil {
		logging.GlobalLogger.Panic("Failed to pack call message ABI values", err)
	}

	// save internalcall
	ichook.callSequenceElement.InternalCall = &calls.InternalCall{
		IsUsed: false,
		Depth:  depth,
		Sender: callee,
		ToAddr: selectedMethod.Address,
		Input:  data,
		Value:  new(big.Int).Set(value),
	}
	// fmt.Println("emit internal call", depth, callee, selectedMethod.Address, abiData.Method.Name, args, value)
	return selectedMethod.Address, data, value
}

func ConvertToContractCall(element *calls.CallSequenceElement) (*calls.CallSequenceElement, error) {
	clonedCall, err := element.Call.Clone()
	if err != nil {
		return element, nil
	}
	call := element.Call
	element.OriginalCall = clonedCall
	element.IsHelperContractCall = true
	element.OriginalContract = element.Contract
	to := *call.To

	method := FuzzHelperContract.CompiledContract().Abi.Methods["sendMsgUtil"]
	abiData := &calls.CallMessageDataAbiValues{
		Method:      &method,
		InputValues: []any{to, call.Data},
	}

	element.Contract = FuzzHelperContract
	element.Call = calls.NewCallMessageWithAbiValueData(call.From, &FuzzHelperContractAddr, 0, call.Value, call.GasLimit, call.GasPrice, call.GasFeeCap, call.GasTipCap, abiData)

	return element, nil
}
