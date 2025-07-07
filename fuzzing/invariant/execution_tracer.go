package invariant

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ethereum/go-ethereum/log"
	// trace "github.com/ethereum/go-ethereum/hunter/trace"
)

const TxTracerResultsKey = "TxTraceResults"

type TxTracer struct {
	callstack []*CallFrame
	gasLimit  uint64

	// record account state
	isRecordState bool
	targetAddress map[common.Address]bool
	env           *vm.EVM
	statedCall    []*CallFrame

	callList []*CallFrame

	// for medusa
	// contractDefinitions represents the contract definitions to match for execution traces.
	contractDefinitions contracts.Contracts

	// cheatCodeContracts  represents the cheat code contract definitions to match for execution traces.
	cheatCodeContracts map[common.Address]*chain.CheatCodeContract
}

func NewTxTracer() *TxTracer {
	return &TxTracer{
		callstack:     make([]*CallFrame, 1),
		targetAddress: make(map[common.Address]bool),
		isRecordState: false,
	}
}

// NewExecutionTracer creates a ExecutionTracer and returns it.
func (t *TxTracer) SetContracts(contractDefinitions contracts.Contracts, cheatCodeContracts map[common.Address]*chain.CheatCodeContract) {
	t.contractDefinitions = contractDefinitions
	t.cheatCodeContracts = cheatCodeContracts
}

func (t *TxTracer) SetRecodingState(addrs []common.Address) {
	t.isRecordState = true
	for _, addr := range addrs {
		t.targetAddress[addr] = true
	}
}

func (t *TxTracer) GetCallFrame() *CallFrame {
	if len(t.callstack) > 0 {
		return t.callstack[0]
	}
	return nil
}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *TxTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.callList = []*CallFrame{}
	t.env = env
	typ := vm.CALL
	if create {
		typ = vm.CREATE
	}
	t.captureEnteredCallFrame(from, to, input, create, value, typ, t.gasLimit, true)
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *TxTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	t.captureExitedCallFrame(output, err)
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *TxTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	// skip if the previous op caused an error
	if err != nil {
		return
	}

	currentCallFrame := t.callstack[len(t.callstack)-1]
	if !currentCallFrame.IsContract {
		currentCallFrame.From = scope.Contract.CallerAddress
		currentCallFrame.To = scope.Contract.Address()
		if scope.Contract.CodeAddr != nil {
			currentCallFrame.CodeAddress = *scope.Contract.CodeAddr
		}
		currentCallFrame.IsContract = true
	}

	if op == vm.SELFDESTRUCT {
		currentCallFrame.SelfDestructed = true
	}

	// recording log
	switch op {
	case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
		size := int(op - vm.LOG0)

		stack := scope.Stack
		stackData := stack.Data()

		// Don't modify the stack
		mStart := stackData[len(stackData)-1]
		mSize := stackData[len(stackData)-2]
		topics := make([]common.Hash, size)
		for i := 0; i < size; i++ {
			topic := stackData[len(stackData)-2-(i+1)]
			topics[i] = common.Hash(topic.Bytes32())
		}

		data, err := getMemoryCopyPadded(scope.Memory, int64(mStart.Uint64()), int64(mSize.Uint64()))
		if err != nil {
			// mSize was unrealistically large
			log.Warn("failed to copy CREATE2 input", "err", err, "tracer", "callTracer", "offset", mStart, "size", mSize)
			return
		}

		log := Log{
			Address:  scope.Contract.Address(),
			Topics:   topics,
			Data:     hexutil.Bytes(data),
			Position: uint(len(currentCallFrame.Calls)),
		}
		currentCallFrame.Logs = append(currentCallFrame.Logs, &log)
	}

	// recording state
	for _, call := range t.statedCall {
		stack := scope.Stack
		stackData := stack.Data()
		stackLen := len(stackData)
		caller := scope.Contract.Address()
		switch {
		case stackLen >= 1 && (op == vm.SLOAD || op == vm.SSTORE):
			slot := common.Hash(stackData[stackLen-1].Bytes32())
			t.lookupStorage(call, caller, slot)
		case stackLen >= 1 && (op == vm.EXTCODECOPY || op == vm.EXTCODEHASH || op == vm.EXTCODESIZE || op == vm.BALANCE || op == vm.SELFDESTRUCT):
			addr := common.Address(stackData[stackLen-1].Bytes20())
			t.lookupAccount(call, addr)
			if op == vm.SELFDESTRUCT {
				call.Deleted[caller] = true
			}
		case stackLen >= 5 && (op == vm.DELEGATECALL || op == vm.CALL || op == vm.STATICCALL || op == vm.CALLCODE):
			addr := common.Address(stackData[stackLen-2].Bytes20())
			t.lookupAccount(call, addr)
			// t.tmpCallLocation = pc
		case op == vm.CREATE:
			nonce := t.env.StateDB.GetNonce(caller)
			addr := crypto.CreateAddress(caller, nonce)
			t.lookupAccount(call, addr)
			call.Created[addr] = true
		case stackLen >= 4 && op == vm.CREATE2:
			offset := stackData[stackLen-2]
			size := stackData[stackLen-3]
			init, err := getMemoryCopyPadded(scope.Memory, int64(offset.Uint64()), int64(size.Uint64()))
			if err != nil {
				log.Warn("failed to copy CREATE2 input", "err", err, "tracer", "prestateTracer", "offset", offset, "size", size)
				return
			}
			inithash := crypto.Keccak256(init)
			salt := stackData[stackLen-4]
			addr := crypto.CreateAddress2(caller, salt.Bytes32(), inithash)
			t.lookupAccount(call, addr)
			call.Created[addr] = true
		}
	}
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *TxTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	t.captureEnteredCallFrame(from, to, input, typ == vm.CREATE || typ == vm.CREATE2, value, typ, gas, false)
}

// captureEnteredCallFrame is a helper method used when a new call frame is entered to record information about it.
func (t *TxTracer) captureEnteredCallFrame(from common.Address, to common.Address, input []byte, isContractCreation bool, value *big.Int, typ vm.OpCode, gas uint64, isStart bool) {
	toCopy := to
	call := CallFrame{
		Type:        typ.String(),
		From:        from,
		To:          toCopy,
		CodeAddress: toCopy,
		Input:       common.CopyBytes(input),
		Gas:         gas,
		Value:       value,
		IsContract:  false,
	}

	// recording state
	// call targetAddrss
	flag1 := ((len(t.targetAddress) > 0 && t.targetAddress[to]) || true)
	// targetAddress calls to others
	// flag2 := len(t.statedCall) > 0 && t.targetAddress[call.From]
	// && (typ == vm.CALL || typ == vm.CREATE || typ == vm.CREATE2 || typ == vm.DELEGATECALL)
	if t.isRecordState && flag1 && (typ == vm.CALL || typ == vm.CREATE || typ == vm.CREATE2 || typ == vm.DELEGATECALL) {
		call.IsState = true
		call.PreState = State{}
		call.PostState = State{}
		call.Created = make(map[common.Address]bool)
		call.Deleted = make(map[common.Address]bool)

		call.Create = isContractCreation
		t.lookupAccount(&call, from)
		t.lookupAccount(&call, to)

		// The recipient balance includes the value transferred.
		toBal := new(big.Int).Sub(call.PreState[to].Balance, value)
		call.PreState[to].Balance = toBal

		// The sender balance is after reducing: value and gasLimit.
		// We need to re-add them to get the pre-tx balance.
		fromBal := new(big.Int).Set(call.PreState[from].Balance)
		fromBal.Add(fromBal, value)
		call.PreState[from].Balance = fromBal

		if isStart {
			call.PreState[from].Nonce--
		}

		if call.Create {
			call.Created[to] = true
		}

		t.statedCall = append(t.statedCall, &call)
	}

	if isStart {
		t.callstack[0] = &call
	} else {
		t.callstack = append(t.callstack, &call)
	}

	// for medusa
	if isContractCreation {
		call.ToInitBytecode = input
	}
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *TxTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	size := len(t.callstack)
	if size <= 1 {
		return
	}
	t.captureExitedCallFrame(output, err)

	// pop call
	call := t.callstack[size-1]
	t.callstack = t.callstack[:size-1]
	size -= 1

	call.GasUsed = gasUsed
	t.callstack[size-1].Calls = append(t.callstack[size-1].Calls, call)

	// append callframe list
	t.callList = append(t.callList, call)
}

// CaptureFault implements the EVMLogger interface to trace an execution fault.
func (t *TxTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}

func (t *TxTracer) CaptureTxStart(gasLimit uint64) {
	t.gasLimit = gasLimit
}

func (t *TxTracer) CaptureTxEnd(restGas uint64) {
	t.callstack[0].GasUsed = t.gasLimit - restGas

	// fmt.Print(t.GetTrace().Log())
	// append callframe list
	t.callList = append(t.callList, t.callstack[0])
	if len(t.callstack) != 1 {
		fmt.Println(t.callstack)
		panic(1)
	}
}

func (t *TxTracer) captureExitedCallFrame(output []byte, err error) {
	currentCallFrame := t.callstack[len(t.callstack)-1]
	processOutput(currentCallFrame, output, err)

	// If this was an initial deployment, now that we're exiting, we'll want to record the finally deployed bytecodes.
	if currentCallFrame.ToRuntimeBytecode == nil {
		// As long as this isn't a failed contract creation, we should be able to fetch "to" byte code on exit.
		if !currentCallFrame.IsContractCreation() || err == nil {
			currentCallFrame.ToRuntimeBytecode = t.env.StateDB.GetCode(currentCallFrame.To)
		}
	}
	if currentCallFrame.CodeRuntimeBytecode == nil {
		// Optimization: If the "to" and "code" addresses match, we can simply set our "code" already fetched "to"
		// runtime bytecode.
		if currentCallFrame.CodeAddress == currentCallFrame.To {
			currentCallFrame.CodeRuntimeBytecode = currentCallFrame.ToRuntimeBytecode
		} else {
			currentCallFrame.CodeRuntimeBytecode = t.env.StateDB.GetCode(currentCallFrame.CodeAddress)
		}
	}

	// Resolve our contract definitions on the call frame data, if they have not been.
	t.resolveCallFrameContractDefinitions(currentCallFrame)

	// recording state
	if t.isRecordState && currentCallFrame.IsState {
		t.handleCallEnd(currentCallFrame)
		t.statedCall = t.statedCall[:len(t.statedCall)-1]
	}
}

// resolveConstructorArgs resolves previously unresolved constructor argument ABI data from the call data, if
// the call frame provided represents a contract deployment.
func (t *TxTracer) resolveCallFrameConstructorArgs(callFrame *CallFrame, contract *contracts.Contract) {
	// If this is a contract creation and the constructor ABI argument data has not yet been resolved, do so now.
	if callFrame.ConstructorArgsData == nil && callFrame.IsContractCreation() {
		// We simply slice the compiled bytecode leading the input data off, and we are left with the constructor
		// arguments ABI data.
		compiledInitBytecode := contract.CompiledContract().InitBytecode
		if len(compiledInitBytecode) <= len(callFrame.Input) {
			callFrame.ConstructorArgsData = callFrame.Input[len(compiledInitBytecode):]
		}
	}
}

// resolveCallFrameContractDefinitions resolves previously unresolved contract definitions for the To and Code addresses
// used within the provided call frame.
func (t *TxTracer) resolveCallFrameContractDefinitions(callFrame *CallFrame) {
	// Try to resolve contract definitions for "to" address
	if callFrame.ToContractAbi == nil {
		// Try to resolve definitions from cheat code contracts
		if cheatCodeContract, ok := t.cheatCodeContracts[callFrame.To]; ok {
			callFrame.ToContractName = cheatCodeContract.Name()
			callFrame.ToContractAbi = cheatCodeContract.Abi()
			callFrame.IsContract = true
		} else {
			// Try to resolve definitions from compiled contracts
			toContract := t.contractDefinitions.MatchBytecode(callFrame.ToInitBytecode, callFrame.ToRuntimeBytecode)
			if toContract != nil {
				callFrame.ToContractName = toContract.Name()
				callFrame.ToContractAbi = &toContract.CompiledContract().Abi
				// callFrame.StorageExtractor = toContract.StorageExtractor()
				callFrame.StorageExtractor = getStorageExtractor(toContract.SourcePath() + ":" + toContract.Name())
				t.resolveCallFrameConstructorArgs(callFrame, toContract)

				// If this is a contract creation, set the code address to the address of the contract we just deployed.
				if callFrame.IsContractCreation() {
					callFrame.CodeContractName = toContract.Name()
					callFrame.CodeContractAbi = &toContract.CompiledContract().Abi
					callFrame.StorageExtractor = getStorageExtractor(toContract.SourcePath() + ":" + toContract.Name())
				}
			}
		}
	}

	// Try to resolve contract definitions for "code" address
	if callFrame.CodeContractAbi == nil {
		// Try to resolve definitions from cheat code contracts
		if cheatCodeContract, ok := t.cheatCodeContracts[callFrame.CodeAddress]; ok {
			callFrame.CodeContractName = cheatCodeContract.Name()
			callFrame.CodeContractAbi = cheatCodeContract.Abi()
			callFrame.IsContract = true
		} else {
			// Try to resolve definitions from compiled contracts
			codeContract := t.contractDefinitions.MatchBytecode(nil, callFrame.CodeRuntimeBytecode)
			if codeContract != nil {
				callFrame.CodeContractName = codeContract.Name()
				callFrame.CodeContractAbi = &codeContract.CompiledContract().Abi
				// callFrame.StorageExtractor = codeContract.StorageExtractor()
				callFrame.StorageExtractor = getStorageExtractor(codeContract.SourcePath() + ":" + codeContract.Name())
			}
		}
	}
}

func (t *TxTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[TxTracerResultsKey] = t.GetTrace()

	// Store executed transaction
	// t.executionTraceList = append(t.executionTraceList, t.GetTrace())
}

func processOutput(f *CallFrame, output []byte, err error) {
	f.Output = slices.Clone(output)
	if err == nil {
		// f.Output = slices.Clone(output)
		return
	}
	f.Error = err
	if f.Type == "CREATE" || f.Type == "CREATE2" {
		f.To = common.HexToAddress("0x")
	}
	if !errors.Is(err, errors.New("execution reverted")) || len(output) == 0 {
		return
	}
	// f.Output = slices.Clone(output)
	if len(output) < 4 {
		return
	}
	if unpacked, err := abi.UnpackRevert(output); err == nil {
		f.RevertReason = unpacked
	}
}

func failed(f *CallFrame) bool {
	return f.Error == nil
}

// clearFailedLogs clears the logs of a callframe and all its children
// in case of execution failure.
func clearFailedLogs(cf *CallFrame, parentFailed bool) {
	failed := failed(cf) || parentFailed
	// Clear own logs
	if failed {
		cf.Logs = nil
	}
	for i := range cf.Calls {
		clearFailedLogs(cf.Calls[i], failed)
	}
}

const (
	memoryPadLimit = 1024 * 1024
)

// GetMemoryCopyPadded returns offset + size as a new slice.
// It zero-pads the slice if it extends beyond memory bounds.
func getMemoryCopyPadded(m *vm.Memory, offset, size int64) ([]byte, error) {
	if offset < 0 || size < 0 {
		return nil, errors.New("offset or size must not be negative")
	}
	if int(offset+size) < m.Len() { // slice fully inside memory
		return m.GetCopy(offset, size), nil
	}
	paddingNeeded := int(offset+size) - m.Len()
	if paddingNeeded > memoryPadLimit {
		return nil, fmt.Errorf("reached limit for padding memory slice: %d", paddingNeeded)
	}
	cpy := make([]byte, size)
	if overlap := int64(m.Len()) - offset; overlap > 0 {
		copy(cpy, m.GetPtr(offset, overlap))
	}
	return cpy, nil
}

// lookupAccount fetches details of an account and adds it to the prestate
// if it doesn't exist there.
func (t *TxTracer) lookupAccount(call *CallFrame, addr common.Address) {
	if _, ok := call.PreState[addr]; ok {
		return
	}

	call.PreState[addr] = &Account{
		Balance: t.env.StateDB.GetBalance(addr),
		Nonce:   t.env.StateDB.GetNonce(addr),
		Code:    t.env.StateDB.GetCode(addr),
		Storage: make(map[common.Hash]common.Hash),
	}
}

// lookupStorage fetches the requested storage slot and adds
// it to the prestate of the given contract. It assumes `lookupAccount`
// has been performed on the contract before.
func (t *TxTracer) lookupStorage(call *CallFrame, addr common.Address, key common.Hash) {
	if _, ok := call.PreState[addr].Storage[key]; ok {
		return
	}
	call.PreState[addr].Storage[key] = t.env.StateDB.GetState(addr, key)
}

func (t *TxTracer) handleCallEnd(call *CallFrame) {
	for addr, state := range call.PreState {
		// The deleted account's state is pruned from `post` but kept in `pre`
		if _, ok := call.Deleted[addr]; ok {
			continue
		}
		postAccount := &Account{Storage: make(map[common.Hash]common.Hash)}
		newBalance := t.env.StateDB.GetBalance(addr)
		newNonce := t.env.StateDB.GetNonce(addr)
		newCode := t.env.StateDB.GetCode(addr)

		postAccount.Balance = newBalance
		postAccount.Nonce = newNonce
		postAccount.Code = newCode

		for key := range state.Storage {
			newVal := t.env.StateDB.GetState(addr, key)
			postAccount.Storage[key] = newVal
		}

		call.PostState[addr] = postAccount
	}
	// the new created contracts' prestate were empty, so delete them
	for a := range call.Created {
		// the created contract maybe exists in statedb before the creating tx
		if s := call.PreState[a]; s != nil && !s.Exists() {
			delete(call.PreState, a)
		}
	}
}

// for medusa
func (t *TxTracer) GetTrace() *ExecutionTrace {
	return &ExecutionTrace{
		TopLevelCallFrame:   t.GetCallFrame(),
		CallList:            t.callList,
		contractDefinitions: t.contractDefinitions,
	}
}

// func (t *TxTracer) ClearTraces() {
// 	t.executionTraceList = []*ExecutionTrace{}
// }

// func (t *TxTracer) GetTraces() []*ExecutionTrace {
// 	return t.executionTraceList
// }
