package bugdetector

import (
	"math/big"

	"github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/logging"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// bugDetectorTracerResultsKey describes the key to use when storing tracer results in call message results,
// or when querying them.
const bugDetectorTracerResultsKey = "BugDetectorTracerResults"

// GetBugDetectorTracerResults obtains BugMap stored by a BugDetectorTracer from message results.
// This is nil if no BugMap were recorded by a tracer (e.g. BugDetectorTracer was not attached during
// this message execution).
func GetBugDetectorTracerResults(messageResults *types.MessageResults) *BugMap {
	// Try to obtain the results the tracer should've stored.
	if genericResult, ok := messageResults.AdditionalResults[bugDetectorTracerResultsKey]; ok {
		if castedResult, ok := genericResult.(*BugMap); ok {
			return castedResult
		}
	}

	// If we could not obtain them, return nil.
	return nil
}

// RemoveBugDetectorTracerResults removes BugMap stored by a BugDetectorTracer from message results.
func RemoveBugDetectorTracerResults(messageResults *types.MessageResults) {
	delete(messageResults.AdditionalResults, bugDetectorTracerResultsKey)
}

// BugDetectorTracer implements vm.EVMLogger to collect information such as coverage maps
// for fuzzing campaigns from EVM execution traces.
type BugDetectorTracer struct {
	helperContract common.Address

	// env is the EVM environment for this call frame.
	env *vm.EVM

	// bugMap describes the dataflow recorded. Call frames which errored are not recorded.
	bugMap *BugMap

	// storageWriteSet describes the dataflow recorded. Call frames which errored are not recorded.
	// storageWriteSet *StorageSet

	// callFrameStates describes the state tracked by the tracer per call frame.
	callFrameStates []*bugDetectorTracerCallFrameState

	// callDepth refers to the current EVM depth during tracing.
	callDepth uint64
}

// bugDetectorTracerCallFrameState tracks state across call frames in the tracer.
type bugDetectorTracerCallFrameState struct {
	// create indicates whether the current call frame is executing on init bytecode (deploying a contract).
	create bool

	// call context
	from       common.Address
	to         common.Address
	isContract bool

	// token transfer flag, including ether transfer and ERC20 transfer
	tokenTransferList []TokenTransfer

	// storageWriteSet
	pendingStorageWriteSet *StorageSet
	pendingStorageReadSet  *StorageSet

	// operation index
	operationIndex uint64

	// has overflow
	overflowPoints map[uint64]bool
}

// NewBugDetectorTracer returns a new BugDetectorTracer.
func NewBugDetectorTracer(helperContract common.Address) *BugDetectorTracer {
	tracer := &BugDetectorTracer{
		helperContract:  helperContract,
		bugMap:          NewBugMap(),
		callFrameStates: make([]*bugDetectorTracerCallFrameState, 0),
		// storageWriteSet: NewStorageSet(),
	}
	return tracer
}

// CaptureTxStart is called upon the start of transaction execution, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureTxStart(gasLimit uint64) {
	// Reset our call frame states
	t.callDepth = 0
	t.bugMap = NewBugMap()
	t.callFrameStates = make([]*bugDetectorTracerCallFrameState, 0)
}

// CaptureTxEnd is called upon the end of transaction execution, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureTxEnd(restGas uint64) {
}

// CaptureStart initializes the tracing operation for the top of a call frame, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.env = env

	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &bugDetectorTracerCallFrameState{
		create:                 create,
		from:                   from,
		to:                     to,
		pendingStorageWriteSet: NewStorageSet(),
		pendingStorageReadSet:  NewStorageSet(),
		overflowPoints:         make(map[uint64]bool),
	})
}

// CaptureEnd is called after a call to finalize tracing completes for the top of a call frame, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	// If we encountered an error in this call frame, mark all dataflow as reverted.
	if err != nil {
		_, revertErr := t.callFrameStates[t.callDepth].pendingStorageWriteSet.RevertAll()
		if revertErr != nil {
			logging.GlobalLogger.Panic("Dataflow tracer failed to update revert dataflow set during capture end", revertErr)
		}
	}

	// check bugs
	t.checkBugs(err)

	// Pop the state tracking struct for this call frame off the stack.
	t.callFrameStates = t.callFrameStates[:t.callDepth]
}

// CaptureEnter is called upon entering of the call frame, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Increase our call depth now that we're entering a new call frame.
	t.callDepth++

	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &bugDetectorTracerCallFrameState{
		create:                 typ == vm.CREATE || typ == vm.CREATE2,
		from:                   from,
		to:                     to,
		pendingStorageWriteSet: NewStorageSet(),
		pendingStorageReadSet:  NewStorageSet(),
		overflowPoints:         make(map[uint64]bool),
	})
}

// CaptureExit is called upon exiting of the call frame, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	// If we encountered an error in this call frame, mark all storage-write as reverted.
	if err != nil {
		_, revertErr := t.callFrameStates[t.callDepth].pendingStorageWriteSet.RevertAll()
		if revertErr != nil {
			logging.GlobalLogger.Panic("Dataflow tracer failed to update revert dataflow set during capture exit", revertErr)
		}
	}

	// Commit all our dataflow sets up one call frame.
	_, _, updateErr := t.callFrameStates[t.callDepth-1].pendingStorageWriteSet.Update(t.callFrameStates[t.callDepth].pendingStorageWriteSet)
	if updateErr != nil {
		logging.GlobalLogger.Panic("Dataflow tracer failed to update dataflow set during capture exit", updateErr)
	}

	// check bugs
	t.checkBugs(err)

	// Pop the state tracking struct for this call frame off the stack.
	t.callFrameStates = t.callFrameStates[:t.callDepth]

	// Decrease our call depth now that we've exited a call frame.
	t.callDepth--
}

// CaptureState records data from an EVM state update, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, vmErr error) {
	// Obtain our call frame state tracking struct
	callFrameState := t.callFrameStates[t.callDepth]

	callFrameState.isContract = true

	switch op {
	case vm.SSTORE:
		slot := scope.Stack.Back(0)
		val := scope.Stack.Back(1)
		storageAddress := scope.Contract.Address()
		codeAddress := scope.Contract.Address()
		if scope.Contract.CodeAddr != nil {
			codeAddress = *scope.Contract.CodeAddr
		}
		// Record storage write for this location in our storage-write set.
		updateErr := callFrameState.pendingStorageWriteSet.SetReadOrWrite(storageAddress, slot, val, codeAddress, callFrameState.create, pc)
		if updateErr != nil {
			logging.GlobalLogger.Panic("Dataflow tracer failed to update dataflow set while tracing state", updateErr)
		}
	case vm.SLOAD:
		slot := scope.Stack.Back(0)
		storageAddress := scope.Contract.Address()
		codeAddress := scope.Contract.Address()
		if scope.Contract.CodeAddr != nil {
			codeAddress = *scope.Contract.CodeAddr
		}
		val := uint256.NewInt(0).SetBytes(t.env.StateDB.GetState(storageAddress, common.Hash(slot.Bytes32())).Bytes())
		// Record storage read for this location in our storage-read set.
		updateErr := callFrameState.pendingStorageReadSet.SetReadOrWrite(storageAddress, slot, val, codeAddress, callFrameState.create, pc)
		if updateErr != nil {
			logging.GlobalLogger.Panic("Dataflow tracer failed to update dataflow set while tracing state", updateErr)
		}
	case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
		size := int(op - vm.LOG0)

		stack := scope.Stack
		stackData := stack.Data()

		topics := make([]common.Hash, size)
		for i := 0; i < size; i++ {
			topic := stackData[len(stackData)-2-(i+1)]
			topics[i] = common.Hash(topic.Bytes32())
		}

		// ERC20 transfer
		if len(topics) > 0 && topics[0].String() == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" && len(topics) == 3 {
			callFrameState.tokenTransferList = append(callFrameState.tokenTransferList, TokenTransfer{
				From:  common.BytesToAddress(topics[1].Bytes()),
				To:    common.BytesToAddress(topics[2].Bytes()),
				Token: scope.Contract.Address(),
			})
		}
	case vm.CALL:
		// Ether transfer
		value := scope.Stack.Back(2)
		if value.Cmp(uint256.NewInt(0)) > 0 {
			callFrameState.tokenTransferList = append(callFrameState.tokenTransferList, TokenTransfer{
				From:   scope.Contract.Address(),
				To:     common.BytesToAddress(scope.Stack.Back(1).Bytes()),
				Token:  common.Address{},
				Amount: uint256.NewInt(0).SetBytes(value.Bytes()),
			})
		}
	}

	if is_overflow(op, scope) {
		callFrameState.overflowPoints[pc] = true
	}

	callFrameState.operationIndex = callFrameState.operationIndex + 1
}

// CaptureFault records an execution fault, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}

// CaptureTxEndSetAdditionalResults can be used to set additional results captured from execution tracing. If this
// tracer is used during transaction execution (block creation), the results can later be queried from the block.
// This method will only be called on the added tracer if it implements the extended TestChainTracer interface.
func (t *BugDetectorTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[bugDetectorTracerResultsKey] = t.bugMap
}

func (t *BugDetectorTracer) checkBugs(execution_err error) {
	if execution_err == nil {
		detect_reentrancy(t)
		detect_overflow(t)
	}
}
