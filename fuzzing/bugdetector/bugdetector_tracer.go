package bugdetector

import (
	"math/big"
	"time"

	"github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

// bugDetectorTracerResultsKey describes the key to use when storing tracer results in call message results,
// or when querying them.
const bugDetectorTracerResultsKey = "BugDetectorTracerResults"

var StartTimeForBugDetector time.Time

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

	// config records the configures for bug detector
	config *config.BugDetectionConfig

	// originalEther is recording the orignal balance of ether, for ether leaking
	originalEther *big.Int

	// adversarial addresses
	adversarialAddresses []common.Address

	helperContract common.Address
}

// bugDetectorTracerCallFrameState tracks state across call frames in the tracer.
type bugDetectorTracerCallFrameState struct {
	// create indicates whether the current call frame is executing on init bytecode (deploying a contract).
	create bool

	// call context
	from        common.Address
	to          common.Address
	codeAddress common.Address
	isContract  bool

	// taint analyzer
	taintAnalyzer *TaintAnalyzer

	// has selfdestruct in sub call
	selfdestructPoints map[string]bool

	// has ehterleaking in sub call
	etherleakingPoints map[string]bool

	// has overflow in sub call
	overflowPoints map[string]bool

	// for reentrancy
	sloadPoints               map[string]TaintStorageSlot
	taintedCallPoints         map[string][]string // []string records the sloadPoints being used in call
	isTouchedAdversialAddress bool
	taintedJUMPIPoints        map[string][]string
}

// NewBugDetectorTracer returns a new BugDetectorTracer.
func NewBugDetectorTracer(helperContract common.Address, config *config.BugDetectionConfig) *BugDetectorTracer {
	tracer := &BugDetectorTracer{
		helperContract:  helperContract,
		bugMap:          NewBugMap(),
		callFrameStates: make([]*bugDetectorTracerCallFrameState, 0),
		config:          config,
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
		create:             create,
		from:               from,
		to:                 to,
		codeAddress:        to,
		taintAnalyzer:      NewTaintAnalyzer(),
		overflowPoints:     make(map[string]bool),
		etherleakingPoints: make(map[string]bool),
		selfdestructPoints: make(map[string]bool),
		taintedCallPoints:  make(map[string][]string),
		sloadPoints:        make(map[string]TaintStorageSlot),
		taintedJUMPIPoints: make(map[string][]string),
	})
}

// CaptureEnd is called after a call to finalize tracing completes for the top of a call frame, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	if err == nil {
		confirm_suicidal(t)
		confirm_etherleaking(t)
		confirm_overflow(t)
	}
	// Pop the state tracking struct for this call frame off the stack.
	t.callFrameStates = t.callFrameStates[:t.callDepth]
}

// CaptureExit is called upon exiting of the call frame, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureExit(output []byte, gasUsed uint64, err error) {

	if err == nil {
		// catch candidated etherleaking
		detect_etherleaking(t)

		// handle the status for reentrancy
		isTouchedAdversialAddress(t)

		// return bugs
		lastCall := t.callFrameStates[len(t.callFrameStates)-1]
		parentCall := t.callFrameStates[len(t.callFrameStates)-2]
		for id := range lastCall.etherleakingPoints {
			parentCall.etherleakingPoints[id] = true
		}
		for id := range lastCall.overflowPoints {
			parentCall.overflowPoints[id] = true
		}
		for id := range lastCall.selfdestructPoints {
			parentCall.selfdestructPoints[id] = true
		}
		// return some status
		parentCall.isTouchedAdversialAddress = parentCall.isTouchedAdversialAddress || lastCall.isTouchedAdversialAddress
	}

	// Pop the state tracking struct for this call frame off the stack.
	t.callFrameStates = t.callFrameStates[:t.callDepth]

	// Decrease our call depth now that we've exited a call frame.
	t.callDepth--
}

// CaptureEnter is called upon entering of the call frame, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Increase our call depth now that we're entering a new call frame.
	t.callDepth++

	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &bugDetectorTracerCallFrameState{
		create:             typ == vm.CREATE || typ == vm.CREATE2,
		from:               from,
		to:                 to,
		codeAddress:        to,
		taintAnalyzer:      NewTaintAnalyzer(),
		overflowPoints:     make(map[string]bool),
		etherleakingPoints: make(map[string]bool),
		selfdestructPoints: make(map[string]bool),
		taintedCallPoints:  make(map[string][]string),
		sloadPoints:        make(map[string]TaintStorageSlot),
		taintedJUMPIPoints: make(map[string][]string),
	})
}

// CaptureState records data from an EVM state update, as defined by vm.EVMLogger.
func (t *BugDetectorTracer) CaptureState(pc uint64, vmOp vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, vmErr error) {
	// Obtain our call frame state tracking struct
	callFrameState := t.callFrameStates[t.callDepth]

	if !callFrameState.isContract {
		callFrameState.isContract = true
		callFrameState.to = scope.Contract.Address() // the proxy address
		callFrameState.codeAddress = *scope.Contract.CodeAddr
	}

	op := byte(vmOp)

	// handle integer overflow detection
	if t.config.IntegerOverflow {
		detect_overflow(t, pc, op, scope)
	}

	// catch candidated suicidal
	if t.config.Suicidal {
		detect_suicidal(t, pc, op)
	}

	// handle block dependency detection
	if t.config.BlockDependency {
		detect_block_dependency(t, pc, op)
	}

	if t.config.Reentrancy {
		detect_reentrancy(t, pc, op, scope)
	}

	if t.config.UnsafeDelegateCall {
		detect_unsafe_delegatecall(t, pc, op, scope)
	}

	// handle taint analysis
	callFrameState.taintAnalyzer.PropagateTaint(op, scope)
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

func (t *BugDetectorTracer) SetOriginalEther(bs []*big.Int) {
	t.originalEther = big.NewInt(0)
	for _, b := range bs {
		t.originalEther = new(big.Int).Add(t.originalEther, b)
	}
}

func (t *BugDetectorTracer) SetAdversarialAddresses(ads []common.Address) {
	for _, addr := range ads {
		t.adversarialAddresses = append(t.adversarialAddresses, addr)
	}
}
