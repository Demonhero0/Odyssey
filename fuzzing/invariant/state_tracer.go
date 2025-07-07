package invariant

import (
	"math/big"

	"github.com/crytic/medusa/chain/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

type StateTracer struct {
	env        *vm.EVM
	SloadSlot  map[common.Address]map[common.Hash]common.Hash
	SStoreSlot map[common.Address]map[common.Hash]common.Hash
	// RelatedSlots map[common.Address]map[common.Hash]common.Hash
	IsTransfer bool

	RecordingSLOAD    bool
	RecordingSSTORE   bool
	RecordingTransfer bool
}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *StateTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.env = env

	t.SloadSlot = make(map[common.Address]map[common.Hash]common.Hash)
	t.SStoreSlot = make(map[common.Address]map[common.Hash]common.Hash)
	// t.RelatedSlots = make(map[common.Address]map[common.Hash]common.Hash)
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *StateTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *StateTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	// skip if the previous op caused an error
	if err != nil {
		return
	}

	if op == vm.SLOAD && t.RecordingSLOAD {
		caller := scope.Contract.Address()
		slot := common.Hash(scope.Stack.Back(0).Bytes32())
		if _, ok := t.SloadSlot[caller]; !ok {
			t.SloadSlot[caller] = make(map[common.Hash]common.Hash)
		}
		t.SloadSlot[caller][slot] = t.env.StateDB.GetState(caller, slot)
		// t.RelatedSlots[caller][slot] = t.env.StateDB.GetState(caller, slot)
	}

	if op == vm.SSTORE && t.RecordingSSTORE {
		caller := scope.Contract.Address()
		slot := common.Hash(scope.Stack.Back(0).Bytes32())
		if _, ok := t.SStoreSlot[caller]; !ok {
			t.SStoreSlot[caller] = make(map[common.Hash]common.Hash)
		}
		t.SStoreSlot[caller][slot] = t.env.StateDB.GetState(caller, slot)
		// t.RelatedSlots[caller][slot] = t.env.StateDB.GetState(caller, slot)
	}

	if t.RecordingTransfer {
		// recording log
		switch op {
		case vm.CALL:
			t.IsTransfer = true
		case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
			size := int(op - vm.LOG0)

			stack := scope.Stack
			stackData := stack.Data()

			// Don't modify the stack
			// mStart := stackData[len(stackData)-1]
			// mSize := stackData[len(stackData)-2]
			topics := make([]common.Hash, size)
			for i := 0; i < size; i++ {
				topic := stackData[len(stackData)-2-(i+1)]
				topics[i] = common.Hash(topic.Bytes32())
			}

			if len(topics) > 0 && topics[0].String() == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" && len(topics) == 3 {
				t.IsTransfer = true
			}
		}
	}
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *StateTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
}

// captureEnteredCallFrame is a helper method used when a new call frame is entered to record information about it.
func (t *StateTracer) captureEnteredCallFrame(from common.Address, to common.Address, input []byte, isContractCreation bool, value *big.Int, typ vm.OpCode, gas uint64, isStart bool) {
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *StateTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
}

// CaptureFault implements the EVMLogger interface to trace an execution fault.
func (t *StateTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}

func (t *StateTracer) CaptureTxStart(gasLimit uint64) {
}

func (t *StateTracer) CaptureTxEnd(restGas uint64) {
}

func (t *StateTracer) captureExitedCallFrame(output []byte, err error) {
}

const StateTraceResultKey = "StateTraceResultKey"

type StateTraceResult struct {
	SloadSlot  map[common.Address]map[common.Hash]common.Hash
	SStoreSlot map[common.Address]map[common.Hash]common.Hash
	// RelatedSlots map[common.Address]map[common.Hash]common.Hash
	IsTransfer bool
}

func (t *StateTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[StateTraceResultKey] = StateTraceResult{
		SloadSlot:  t.SloadSlot,
		SStoreSlot: t.SStoreSlot,
		// RelatedSlots: t.RelatedSlots,
		IsTransfer: t.IsTransfer,
	}
}
