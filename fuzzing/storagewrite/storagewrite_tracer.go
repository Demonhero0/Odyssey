package storagewrite

import (
	"math/big"

	"github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/logging"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

// storageWriteTracerResultsKey describes the key to use when storing tracer results in call message results,
// or when querying them.
const storageWriteTracerResultsKey = "StorageWriteTracerResults"

// GetStorageWriteTracerResults obtains StorageWriteSet stored by a StorageWriteTracer from message results.
// This is nil if no StorageWriteSet were recorded by a tracer (e.g. StorageWriteTracer was not attached during
// this message execution).
func GetStorageWriteTracerResults(messageResults *types.MessageResults) *StorageWriteSet {
	// Try to obtain the results the tracer should've stored.
	if genericResult, ok := messageResults.AdditionalResults[storageWriteTracerResultsKey]; ok {
		if castedResult, ok := genericResult.(*StorageWriteSet); ok {
			return castedResult
		}
	}

	// If we could not obtain them, return nil.
	return nil
}

// RemoveStorageWriteTracerResults removes StorageWriteSet stored by a StorageWriteTracer from message results.
func RemoveStorageWriteTracerResults(messageResults *types.MessageResults) {
	delete(messageResults.AdditionalResults, storageWriteTracerResultsKey)
}

// StorageWriteTracer implements vm.EVMLogger to collect information such as coverage maps
// for fuzzing campaigns from EVM execution traces.
type StorageWriteTracer struct {
	// storageWriteSet describes the dataflow recorded. Call frames which errored are not recorded.
	storageWriteSet *StorageWriteSet

	// callFrameStates describes the state tracked by the tracer per call frame.
	callFrameStates []*storageWriteTracerCallFrameState

	// callDepth refers to the current EVM depth during tracing.
	callDepth uint64
}

// storageWriteTracerCallFrameState tracks state across call frames in the tracer.
type storageWriteTracerCallFrameState struct {
	// create indicates whether the current call frame is executing on init bytecode (deploying a contract).
	create bool

	// pendingStorageWriteSet describes the storage-write set recorded for this call frame.
	pendingStorageWriteSet *StorageWriteSet
}

// NewStorageWriteTracer returns a new StorageWriteTracer.
func NewStorageWriteTracer() *StorageWriteTracer {
	tracer := &StorageWriteTracer{
		storageWriteSet: NewStorageWriteSet(),
		callFrameStates: make([]*storageWriteTracerCallFrameState, 0),
	}
	return tracer
}

// CaptureTxStart is called upon the start of transaction execution, as defined by vm.EVMLogger.
func (t *StorageWriteTracer) CaptureTxStart(gasLimit uint64) {
	// Reset our call frame states
	t.callDepth = 0
	t.storageWriteSet = NewStorageWriteSet()
	t.callFrameStates = make([]*storageWriteTracerCallFrameState, 0)
}

// CaptureTxEnd is called upon the end of transaction execution, as defined by vm.EVMLogger.
func (t *StorageWriteTracer) CaptureTxEnd(restGas uint64) {
}

// CaptureStart initializes the tracing operation for the top of a call frame, as defined by vm.EVMLogger.
func (t *StorageWriteTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &storageWriteTracerCallFrameState{
		create:                 create,
		pendingStorageWriteSet: NewStorageWriteSet(),
	})
}

// CaptureEnd is called after a call to finalize tracing completes for the top of a call frame, as defined by vm.EVMLogger.
func (t *StorageWriteTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	// If we encountered an error in this call frame, mark all dataflow as reverted.
	if err != nil {
		_, revertErr := t.callFrameStates[t.callDepth].pendingStorageWriteSet.RevertAll()
		if revertErr != nil {
			logging.GlobalLogger.Panic("Dataflow tracer failed to update revert dataflow set during capture end", revertErr)
		}
	}

	// Commit all our coverage maps up one call frame.
	_, _, updateErr := t.storageWriteSet.Update(t.callFrameStates[t.callDepth].pendingStorageWriteSet)
	if updateErr != nil {
		logging.GlobalLogger.Panic("Dataflow tracer failed to update dataflow set during capture end", updateErr)
	}

	// Pop the state tracking struct for this call frame off the stack.
	t.callFrameStates = t.callFrameStates[:t.callDepth]
}

// CaptureEnter is called upon entering of the call frame, as defined by vm.EVMLogger.
func (t *StorageWriteTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Increase our call depth now that we're entering a new call frame.
	t.callDepth++

	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &storageWriteTracerCallFrameState{
		create:                 typ == vm.CREATE || typ == vm.CREATE2,
		pendingStorageWriteSet: NewStorageWriteSet(),
	})
}

// CaptureExit is called upon exiting of the call frame, as defined by vm.EVMLogger.
func (t *StorageWriteTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
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

	// Pop the state tracking struct for this call frame off the stack.
	t.callFrameStates = t.callFrameStates[:t.callDepth]

	// Decrease our call depth now that we've exited a call frame.
	t.callDepth--
}

// CaptureState records data from an EVM state update, as defined by vm.EVMLogger.
func (t *StorageWriteTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, vmErr error) {
	// Obtain our call frame state tracking struct
	callFrameState := t.callFrameStates[t.callDepth]

	if op == vm.SSTORE {
		slot := scope.Stack.Back(0)
		val := scope.Stack.Back(1)
		storageAddress := scope.Contract.Address()
		codeAddress := scope.Contract.Address()
		if scope.Contract.CodeAddr != nil {
			codeAddress = *scope.Contract.CodeAddr
		}
		// Record storage write for this location in our storage-write set.
		_, updateErr := callFrameState.pendingStorageWriteSet.SetWrite(storageAddress, slot, val, codeAddress, callFrameState.create, pc)
		if updateErr != nil {
			logging.GlobalLogger.Panic("Dataflow tracer failed to update dataflow set while tracing state", updateErr)
		}
	}
}

// CaptureFault records an execution fault, as defined by vm.EVMLogger.
func (t *StorageWriteTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}

// CaptureTxEndSetAdditionalResults can be used to set additional results captured from execution tracing. If this
// tracer is used during transaction execution (block creation), the results can later be queried from the block.
// This method will only be called on the added tracer if it implements the extended TestChainTracer interface.
func (t *StorageWriteTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[storageWriteTracerResultsKey] = t.storageWriteSet
}
