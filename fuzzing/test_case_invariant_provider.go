package fuzzing

import (
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/crytic/medusa/fuzzing/calls"
	fuzzerTypes "github.com/crytic/medusa/fuzzing/contracts"
	fuzzingTypes "github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/invariant"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// InvariantTestCaseProvider is a provider for on-chain property tests.
// Property tests are represented as publicly-accessible view functions which have a name prefix specified by a
// config.FuzzingConfig. They take no input arguments and return a boolean indicating whether the test passed.
// If a call to any on-chain property test returns false, the test signals a failed status. If no failure is found
// before the fuzzing campaign ends, the test signals a passed status.
type InvariantCheckerProvider struct {
	// fuzzer describes the Fuzzer which this provider is attached to.
	fuzzer *Fuzzer

	// testCases is a map of contract-method IDs to property test cases.GetContractMethodID
	invariantCheckers map[string]*InvariantChecker

	// testCasesLock is used for thread-synchronization when updating testCases
	invariantCheckersLock sync.Mutex

	// workerStates is a slice where each element stores state for a given worker index.
	workerStates []InvariantCheckerProviderWorkerState
}

// InvariantTestCaseProviderWorkerState represents the state for an individual worker maintained by
// InvariantTestCaseProvider.
type InvariantCheckerProviderWorkerState struct {
	// propertyTestMethods a mapping from contract-method ID to deployed contract-method descriptors.
	// Each deployed contract-method represents a property test method to call for evaluation. Property tests
	// should be read-only (pure/view) functions which take no input parameters and return a boolean variable
	// indicating if the property test passed.
	invariantCheckerMethodMap    map[string]InvariantCheckerMethod
	invariantState               map[string]*invariant.StateValue
	postStateVariablesFuncs      []InvariantPostStateFunc
	invariantCheckerProviderLock sync.Mutex
}

type InvariantPostStateFunc func(worker *FuzzerWorker) error

type InvariantCheckerMethod struct {
	CheckerId string
	Address   common.Address
	Contract  *fuzzingTypes.Contract
	MethodSig string
	CheckFunc InvariantCheckerFunc
	Pattern   *InvariantPattern
}

// attachInvariantTestCaseProvider attaches a new InvariantTestCaseProvider to the Fuzzer and returns it.
func attachInvariantTestCaseProvider(fuzzer *Fuzzer) *InvariantCheckerProvider {

	// Create a test case provider
	t := &InvariantCheckerProvider{
		fuzzer: fuzzer,
	}

	// Subscribe the provider to relevant events the fuzzer emits.
	fuzzer.Events.FuzzerStarting.Subscribe(t.onFuzzerStarting)
	fuzzer.Events.FuzzerStopping.Subscribe(t.onFuzzerStopping)
	fuzzer.Events.WorkerCreated.Subscribe(t.onWorkerCreated)

	// Add the provider's call sequence test function to the fuzzer.
	// fuzzer.Hooks.CallSequenceTestFuncs = append(fuzzer.Hooks.CallSequenceTestFuncs, t.callSequencePostCheck)
	fuzzer.Hooks.GetInvariantPreStateFunc = t.getInvariantPreState
	fuzzer.Hooks.GetInvariantPostStateFunc = t.getInvariantPostState
	fuzzer.Hooks.InvariantCheckFuncs = append(fuzzer.Hooks.InvariantCheckFuncs, t.callSequencePostCheck)
	return t
}

func (t *InvariantCheckerProvider) getCheckerId(contract *fuzzerTypes.Contract, address, method string) string {
	if t.fuzzer.config.Fuzzing.OnChainFuzzingConfig.IsOnChain {
		return getCheckerIdWithAddress(address, method)
	} else {
		return getCheckerIdWithContract(contract, method)
	}
}

func getCheckerIdWithContract(contract *fuzzerTypes.Contract, method string) string {
	return strings.Join([]string{contract.SourcePath(), contract.Name(), method}, "/")
}

func getCheckerIdWithAddress(address, methodSig string) string {
	return strings.Join([]string{strings.ToLower(address), methodSig}, ":")
}

// checkPropertyTestFailed executes a given property test method to see if it returns a failed status. This is used to
// facilitate testing of property test methods after every call the Fuzzer makes when testing call sequences.
// A boolean indicating whether an execution trace should be captured and returned is provided to the method.
// Returns a boolean indicating if the property test failed, an optional execution trace for the property test call,
// or an error if one occurred.
func (t *InvariantCheckerProvider) checkInvariantViolation(worker *FuzzerWorker, invariantCheckerMethod *InvariantCheckerMethod, callSequence calls.CallSequence) (bool, *big.Int, string, error) {

	invariantViolation := false
	var flag string
	var formatStr string
	var distance *big.Int

	// check if execution revert
	callSequenceElement := callSequence[len(callSequence)-1]
	block := callSequenceElement.ChainReference.Block
	messageResult := block.MessageResults[callSequenceElement.ChainReference.TransactionIndex]
	if messageResult.ExecutionResult.Err != nil {
		return invariantViolation, distance, formatStr, nil
	}

	workerState := &t.workerStates[worker.WorkerIndex()]
	invariantState := workerState.invariantState

	if isGlobalInv(invariantCheckerMethod.CheckerId) {
		if invariantCheckerMethod.MethodSig == "profitable" {
			flag, distance, formatStr = invariantCheckerMethod.CheckFunc(invariantState)
		} else if invariantCheckerMethod.MethodSig == "moreBalance" {
			flag, distance, formatStr = invariantCheckerMethod.CheckFunc(invariantState)
		} else if invariantCheckerMethod.MethodSig == "selfdestruct" {
			for _, deploymentChange := range messageResult.ContractDeploymentChanges {
				if deploymentChange.Destroyed {
					flag, distance, formatStr = "violation", big.NewInt(-1), fmt.Sprintf("%s:selfdestruct", deploymentChange.Contract.Address.String())
				}
			}
		} else {
			flag, distance, formatStr = invariantCheckerMethod.CheckFunc(workerState.invariantState)
		}
	} else {
		var call *calls.CallMessage
		var contract *fuzzerTypes.Contract
		if callSequenceElement.IsHelperContractCall {
			call = callSequenceElement.OriginalCall
			contract = callSequenceElement.OriginalContract
		} else {
			call = callSequenceElement.Call
			contract = callSequenceElement.Contract
		}
		if isERC20Inv(invariantCheckerMethod.CheckerId) {
			if invariantCheckerMethod.MethodSig == call.DataAbiValues.Method.Sig {
				flag, distance, formatStr = invariantCheckerMethod.CheckFunc(workerState.invariantState)
			}
		} else {
			if t.isMatchContractInv(invariantCheckerMethod, call, contract) {
				flag, distance, formatStr = invariantCheckerMethod.CheckFunc(workerState.invariantState)
			}
		}
	}

	if flag == "violation" {
		invariantViolation = true
	}

	// Return our property test results
	return invariantViolation, distance, formatStr, nil
}

// onFuzzerStarting is the event handler triggered when the Fuzzer is starting a fuzzing campaign. It creates test cases
// in a "not started" state for every property test method discovered in the contract definitions known to the Fuzzer.
func (t *InvariantCheckerProvider) onFuzzerStarting(event FuzzerStartingEvent) error {
	// Reset our state
	t.invariantCheckers = make(map[string]*InvariantChecker)
	t.workerStates = make([]InvariantCheckerProviderWorkerState, t.fuzzer.Config().Fuzzing.Workers)

	if t.fuzzer.config.Fuzzing.OnChainFuzzingConfig.IsOnChain {
		return t.onFuzzerStartingOnChain(event)
	} else {
		return t.onFuzzerStartingOffChain(event)
	}
}

func (t *InvariantCheckerProvider) onFuzzerStartingOnChain(event FuzzerStartingEvent) error {
	invariantJson := LoadInvariantsFromJson(t.fuzzer.Config().Fuzzing.Testing.InvariantChecking.JsonPath)
	for address := range invariantJson {
		for methodSig, invariantPattern := range invariantJson[address] {
			invariantChecker := &InvariantChecker{
				status: TestCaseStatusNotStarted,
				// targetContract:   contract,
				targetMethod:     methodSig,
				callSequence:     nil,
				InvariantPattern: invariantPattern,
				isOnChain:        true,
				targetAddress:    strings.ToLower(address),
			}
			checkerId := getCheckerIdWithAddress(strings.ToLower(address), methodSig)
			t.invariantCheckers[checkerId] = invariantChecker
			t.fuzzer.RegisterTestCase(invariantChecker)
		}
	}
	return nil
}

func (t *InvariantCheckerProvider) onFuzzerStartingOffChain(event FuzzerStartingEvent) error {
	invariantJson := LoadInvariantsFromJson(t.fuzzer.Config().Fuzzing.Testing.InvariantChecking.JsonPath)
	// Create a test case for every property test method.
	for _, contract := range t.fuzzer.ContractDefinitions() {
		// Create local variables to avoid pointer types in the loop being overridden.
		invariantContract, existInvariantContract := invariantJson[contract.Name()]

		if !existInvariantContract {
			continue
		}

		// handle contract invariant
		if invariantPattern, ok := invariantContract["contract"]; ok {
			flag, err := checkInvariant(invariantPattern)
			if !flag {
				return fmt.Errorf("error in onFuzzingStart:%v", err)
			}
			invariantChecker := &InvariantChecker{
				status:           TestCaseStatusNotStarted,
				targetContract:   contract,
				targetMethod:     "contract",
				callSequence:     nil,
				InvariantPattern: invariantPattern,
			}

			checkerId := getCheckerIdWithContract(contract, "contract")
			t.invariantCheckers[checkerId] = invariantChecker
			t.fuzzer.RegisterTestCase(invariantChecker)
		}

		for _, method := range contract.CompiledContract().Abi.Methods {
			contract := contract
			method := method

			invariantPattern, existInvariantFunction := invariantContract[method.Sig]
			if !existInvariantFunction {
				continue
			}
			flag, err := checkInvariant(invariantPattern)
			if !flag {
				return fmt.Errorf("error in onFuzzingStart:%v", err)
			}

			invariantChecker := &InvariantChecker{
				status:           TestCaseStatusNotStarted,
				targetContract:   contract,
				targetMethod:     method.Sig,
				callSequence:     nil,
				InvariantPattern: invariantPattern,
			}

			checkerId := getCheckerIdWithContract(contract, method.Sig)
			t.invariantCheckers[checkerId] = invariantChecker
			t.fuzzer.RegisterTestCase(invariantChecker)
		}
	}

	for address := range invariantJson {
		if address == "0x" || address == "erc20" {
			for methodSig, invariantPattern := range invariantJson[address] {
				invariantChecker := &InvariantChecker{
					status: TestCaseStatusNotStarted,
					// targetContract:   contract,
					targetMethod:     methodSig,
					callSequence:     nil,
					InvariantPattern: invariantPattern,
					isOnChain:        true,
					targetAddress:    strings.ToLower(address),
				}
				checkerId := getCheckerIdWithAddress(strings.ToLower(address), methodSig)
				t.invariantCheckers[checkerId] = invariantChecker
				t.fuzzer.RegisterTestCase(invariantChecker)
			}
		}
	}
	return nil
}

// onFuzzerStopping is the event handler triggered when the Fuzzer is stopping the fuzzing campaign and all workers
// have been destroyed. It clears state tracked for each FuzzerWorker and sets test cases in "running" states to
// "passed".
func (t *InvariantCheckerProvider) onFuzzerStopping(event FuzzerStoppingEvent) error {
	// Clear our property test methods
	t.workerStates = nil

	// Loop through each test case and set any tests with a running status to a passed status.
	for _, invariantChecker := range t.invariantCheckers {
		if invariantChecker.status == TestCaseStatusRunning {
			invariantChecker.status = TestCaseStatusPassed
		}
	}
	return nil
}

func isGlobalInv(s string) bool {
	return strings.HasPrefix(s, "0x:")
}

func isERC20Inv(s string) bool {
	return strings.HasPrefix(s, "erc20:")
}

// onWorkerCreated is the event handler triggered when a FuzzerWorker is created by the Fuzzer. It ensures state tracked
// for that worker index is refreshed and subscribes to relevant worker events.
func (t *InvariantCheckerProvider) onWorkerCreated(event FuzzerWorkerCreatedEvent) error {
	// Create a new state for this worker.
	t.workerStates[event.Worker.WorkerIndex()] = InvariantCheckerProviderWorkerState{
		invariantCheckerMethodMap:    make(map[string]InvariantCheckerMethod),
		invariantState:               make(map[string]*invariant.StateValue),
		invariantCheckerProviderLock: sync.Mutex{},
	}

	// Subscribe to relevant worker events.
	event.Worker.Events.ContractAdded.Subscribe(t.onWorkerDeployedContractAdded)
	event.Worker.Events.ContractDeleted.Subscribe(t.onWorkerDeployedContractDeleted)

	for checkerId := range t.invariantCheckers {
		if isGlobalInv(checkerId) || isERC20Inv(checkerId) {
			t.invariantCheckersLock.Lock()
			invariantChecker, invariantCheckerExists := t.invariantCheckers[checkerId]
			t.invariantCheckersLock.Unlock()
			if invariantCheckerExists {
				if invariantChecker.Status() == TestCaseStatusNotStarted {
					invariantChecker.status = TestCaseStatusRunning
				}
				if invariantChecker.Status() != TestCaseStatusFailed {
					// Create our property test method reference.
					workerState := &t.workerStates[event.Worker.WorkerIndex()]
					workerState.invariantCheckerProviderLock.Lock()
					icm := InvariantCheckerMethod{
						CheckerId: checkerId,
						MethodSig: invariantChecker.targetMethod,
						CheckFunc: invariantChecker.getInvariantCheckerFunc(),
						Pattern:   invariantChecker.InvariantPattern,
					}
					workerState.invariantCheckerMethodMap[checkerId] = icm
					workerState.invariantCheckerProviderLock.Unlock()
				}
			}
		}
	}

	return nil
}

// onWorkerDeployedContractAdded is the event handler triggered when a FuzzerWorker detects a new contract deployment
// on its underlying chain. It ensures any property test methods which the deployed contract contains are tracked by the
// provider for testing. Any test cases previously made for these methods which are in a "not started" state are put
// into a "running" state, as they are now potentially reachable for testing.
func (t *InvariantCheckerProvider) onWorkerDeployedContractAdded(event FuzzerWorkerContractAddedEvent) error {
	if event.ContractDefinition == nil {
		return nil
	}

	contractMethodList := []string{"contract"}
	for _, method := range event.ContractDefinition.CompiledContract().Abi.Methods {
		contractMethodList = append(contractMethodList, method.Sig)
		if implementation, ok := t.fuzzer.proxyContractMap[event.ContractAddress]; ok {
			bytecodes, _ := t.fuzzer.fuzzerInitAccountState.initAccountState.GetCode(implementation)

			// Try to match it to a known contract definition
			matchedDefinition := t.fuzzer.contractDefinitions.MatchBytecode(nil, bytecodes)
			if matchedDefinition != nil {
				for _, m := range matchedDefinition.CompiledContract().Abi.Methods {
					if !m.IsConstant() {
						contractMethodList = append(contractMethodList, m.Sig)
					}
				}
			}
		}
	}

	for _, methodSig := range contractMethodList {
		// deal with contract invariant
		checkerId := t.getCheckerId(event.ContractDefinition, strings.ToLower(event.ContractAddress.Hex()), methodSig)

		t.invariantCheckersLock.Lock()
		invariantChecker, invariantCheckerExists := t.invariantCheckers[checkerId]
		t.invariantCheckersLock.Unlock()
		if invariantCheckerExists {
			if invariantChecker.Status() == TestCaseStatusNotStarted {
				invariantChecker.status = TestCaseStatusRunning
			}
			if invariantChecker.Status() != TestCaseStatusFailed {
				// Create our property test method reference.
				workerState := &t.workerStates[event.Worker.WorkerIndex()]
				workerState.invariantCheckerProviderLock.Lock()
				workerState.invariantCheckerMethodMap[checkerId] = InvariantCheckerMethod{
					CheckerId: checkerId,
					Address:   event.ContractAddress,
					Contract:  event.ContractDefinition,
					MethodSig: invariantChecker.targetMethod,
					CheckFunc: invariantChecker.getInvariantCheckerFunc(),
					Pattern:   invariantChecker.InvariantPattern,
				}
				workerState.invariantCheckerProviderLock.Unlock()
			}
		}
	}

	return nil
}

// onWorkerDeployedContractDeleted is the event handler triggered when a FuzzerWorker detects that a previously deployed
// contract no longer exists on its underlying chain. It ensures any property test methods which the deployed contract
// contained are no longer tracked by the provider for testing.
func (t *InvariantCheckerProvider) onWorkerDeployedContractDeleted(event FuzzerWorkerContractDeletedEvent) error {
	return nil
}

// callSequencePostCallTest provides is a CallSequenceTestFunc that performs post-call testing logic for the attached Fuzzer
// and any underlying FuzzerWorker. It is called after every call made in a call sequence. It checks whether property
// test invariants are upheld after each call the Fuzzer makes when testing a call sequence.
func (t *InvariantCheckerProvider) callSequencePostCheck(worker *FuzzerWorker, callSequence calls.CallSequence, lowestDistance *big.Int) ([]ShrinkCallSequenceRequest, error) {

	// Create a list of shrink call sequence verifiers, which we populate for each failed property test we want a call
	// sequence shrunk for.
	shrinkRequests := make([]ShrinkCallSequenceRequest, 0)

	// Obtain the test provider state for this worker
	workerState := &t.workerStates[worker.WorkerIndex()]

	// targetMethodNames := []string{"transfer"}
	// lastCallElement := callSequence[len(callSequence)-1]
	// for _, targetMethodName := range targetMethodNames {
	// 	if lastCallElement.OriginalCall != nil && lastCallElement.OriginalCall.DataAbiValues.Method.Name == targetMethodName || lastCallElement.Call.DataAbiValues.Method.Name == targetMethodName {
	// 		block := lastCallElement.ChainReference.Block
	// 		messageResult := block.MessageResults[lastCallElement.ChainReference.TransactionIndex]
	// 		executionTrace := messageResult.AdditionalResults["executionTracerDebug"].(*executiontracer.ExecutionTrace)
	// 		// if lastCallElement.InternalCall != nil && hex.EncodeToString(lastCallElement.InternalCall.Input[:4]) == "f3fef3a3" {
	// 		if messageResult.ExecutionResult.Err == nil {
	// 			fmt.Print(lastCallElement.String())
	// 			fmt.Print(executionTrace.Log())
	// 			for name, stateValue := range workerState.invariantState {
	// 				fmt.Println(name, stateValue.Value)
	// 			}
	// 		}
	// 	}
	// }

	// for _, callElement := range callSequence {
	// 	block := callElement.ChainReference.Block
	// 	messageResult := block.MessageResults[callElement.ChainReference.TransactionIndex]
	// 	executionTrace, _ := messageResult.AdditionalResults["executionTracerDebug"].(*executiontracer.ExecutionTrace)
	// 	fmt.Println(executionTrace.String())
	// }

	for checkerId, invariantCheckerMethod := range workerState.invariantCheckerMethodMap {
		t.invariantCheckersLock.Lock()
		invariantChecker := t.invariantCheckers[checkerId]
		t.invariantCheckersLock.Unlock()

		if invariantChecker.Status() == TestCaseStatusFailed {
			continue
		}

		invariantCheckerMethod := invariantCheckerMethod
		violatedInvariantFlag, _, _, err := t.checkInvariantViolation(worker, &invariantCheckerMethod, callSequence)
		if err != nil {
			return nil, err
		}

		// if workerState.invariantState["pre(balance)"].Value.(*big.Int).Cmp(workerState.invariantState["post(balance)"].Value.(*big.Int)) == -1 {
		// 	for name := range workerState.invariantState {
		// 		fmt.Println(name, workerState.invariantState[name])
		// 	}
		// 	fmt.Print("--------------\n")
		// }

		if violatedInvariantFlag {
			// fmt.Println(invariantCheckerMethod.MethodSig)
			// for _, callElement := range callSequence {
			// 	block := callElement.ChainReference.Block
			// 	messageResult := block.MessageResults[callElement.ChainReference.TransactionIndex]
			// 	if messageResult.ExecutionResult.Err == nil {
			// 		fmt.Println(callElement.String())
			// 		// executionTrace, _ := messageResult.AdditionalResults["executionTracerDebug"].(*executiontracer.ExecutionTrace)
			// 		// fmt.Println(executionTrace.String())
			// 	}
			// }
			shrinkRequest := ShrinkCallSequenceRequest{
				VerifierFunction: func(worker *FuzzerWorker, shrunkenCallSequence calls.CallSequence) (bool, error) {
					// shrink verifier simply ensures the previously failed property test fails
					// for the shrunk sequence as well.
					var shrunkenSequenceFailedTest bool
					var err error
					shrunkenSequenceFailedTest, _, _, err = t.checkInvariantViolation(worker, &invariantCheckerMethod, shrunkenCallSequence)
					return shrunkenSequenceFailedTest, err
				},
				FinishedCallback: func(worker *FuzzerWorker, shrunkenCallSequence calls.CallSequence) error {
					// When we're finished shrinking, attach an execution trace to the last call
					if len(shrunkenCallSequence) > 0 {
						err = shrunkenCallSequence[len(shrunkenCallSequence)-1].AttachExecutionTrace(worker.chain, worker.fuzzer.contractDefinitions)
						if err != nil {
							return err
						}
					}

					// Execute the property test a final time, this time obtaining an execution trace
					var (
						shrunkenSequenceFailedTest bool
						distance                   *big.Int
						violationCase              string
						err                        error
					)
					if invariantCheckerMethod.MethodSig == "moreBalance" {
						profitableCheckerMethod := workerState.invariantCheckerMethodMap["profitable"]
						shrunkenSequenceFailedTest, distance, violationCase, err = t.checkInvariantViolation(worker, &profitableCheckerMethod, shrunkenCallSequence)
						if err != nil {
							return err
						}
						if !shrunkenSequenceFailedTest {
							return nil
						}
					} else {
						shrunkenSequenceFailedTest, distance, violationCase, err = t.checkInvariantViolation(worker, &invariantCheckerMethod, shrunkenCallSequence)
						if err != nil {
							return err
						}
						if !shrunkenSequenceFailedTest {
							return fmt.Errorf("invariant checker did not fail on final shrunken sequence %s", invariantCheckerMethod.Pattern.Str)
						}
					}

					// Update our test state and report it finalized.
					invariantChecker.status = TestCaseStatusFailed
					invariantChecker.ViolationCase = fmt.Sprintf("%s = %s", violationCase, distance.String())
					invariantChecker.callSequence = &shrunkenCallSequence
					worker.Fuzzer().ReportTestCaseFinished(invariantChecker)

					// for update corpus
					if invariantChecker.InvariantPattern.Level == "warning" {
						if worker.fuzzer.config.Fuzzing.Testing.InvariantChecking.InvariantGuided {
							err = worker.fuzzer.corpus.AddSequence(shrunkenCallSequence, worker.getNewCorpusCallSequenceWeight(), true)
							if err != nil {
								return fmt.Errorf("error in AddSequence: %v", err)
							}
						}
					}
					return nil
				},
				RecordResultInCorpus: true,
			}

			// Add our shrink request to our list.
			shrinkRequests = append(shrinkRequests, shrinkRequest)
		}
		// else if worker.fuzzer.config.Fuzzing.Testing.InvariantChecking.InvariantGuided && distance != nil {
		// 	worker.fuzzer.corpus.CheckSequenceInvariantAndUpdate(callSequence, worker.getNewCorpusCallSequenceWeight(), true, checkerId, distance)
		// }
	}
	return shrinkRequests, nil
}

func (t *InvariantCheckerProvider) isMatchContractInv(invariantCheckerMethod *InvariantCheckerMethod, call *calls.CallMessage, contract *fuzzerTypes.Contract) bool {
	if t.fuzzer.config.Fuzzing.OnChainFuzzingConfig.IsOnChain {
		if *call.To == common.Address(invariantCheckerMethod.Address) {
			return invariantCheckerMethod.MethodSig == "contract" || invariantCheckerMethod.MethodSig == call.DataAbiValues.Method.Sig
		}
	} else {
		if strings.Join([]string{contract.SourcePath(), contract.Name()}, "/") == strings.Join([]string{invariantCheckerMethod.Contract.SourcePath(), invariantCheckerMethod.Contract.Name()}, "/") {
			return invariantCheckerMethod.MethodSig == "contract" || invariantCheckerMethod.MethodSig == call.DataAbiValues.Method.Sig
		}
	}
	return false
}

func (t *InvariantCheckerProvider) isTargetInvariantCheckerMethod(invariantCheckerMethod *InvariantCheckerMethod, call *calls.CallMessage, contract *fuzzerTypes.Contract) bool {
	if isGlobalInv(invariantCheckerMethod.CheckerId) {
		return true
	} else if isERC20Inv(invariantCheckerMethod.CheckerId) {
		return invariantCheckerMethod.MethodSig == "contract" || invariantCheckerMethod.MethodSig == call.DataAbiValues.Method.Sig
	} else {
		return t.isMatchContractInv(invariantCheckerMethod, call, contract)
	}
}

func (t *InvariantCheckerProvider) getInvariantPreState(worker *FuzzerWorker, callSequenceElement *calls.CallSequenceElement) error {
	// Obtain the test provider state for this worker
	workerState := &t.workerStates[worker.WorkerIndex()]
	workerState.invariantState = make(map[string]*invariant.StateValue)
	workerState.postStateVariablesFuncs = []InvariantPostStateFunc{}
	for checkerId, invariantCheckerMethod := range workerState.invariantCheckerMethodMap {
		t.invariantCheckersLock.Lock()
		invariantChecker := t.invariantCheckers[checkerId]
		t.invariantCheckersLock.Unlock()

		if invariantChecker.Status() == TestCaseStatusFailed {
			continue
		}

		var call *calls.CallMessage
		var contract *fuzzingTypes.Contract
		if callSequenceElement.IsHelperContractCall {
			call = callSequenceElement.OriginalCall
			contract = callSequenceElement.OriginalContract
		} else {
			call = callSequenceElement.Call
			contract = callSequenceElement.Contract
		}

		if !t.isTargetInvariantCheckerMethod(&invariantCheckerMethod, call, contract) {
			continue
		}

		// fmt.Println(checkerId, invariantCheckerMethod.MethodSig, call.DataAbiValues.Method.Sig)

		invariantPattern := invariantCheckerMethod.Pattern
		// deal with oriVarNames
		if len(invariantPattern.OriStateVarNames) > 0 {
			t.getOriStateVariables(worker, invariantPattern.OriStateVarNames)
		}

		// deal with msgVarNames
		if len(invariantPattern.MsgVarNames) > 0 {
			for _, name := range invariantPattern.MsgVarNames {
				if name == "sender" {
					workerState.invariantState[name] = &invariant.StateValue{
						Value: callSequenceElement.Call.From,
						Type:  "address",
					}
				} else {
					panic(fmt.Sprintf("not support %s in msgVarNames", name))
				}
			}
		}

		// deal with inputVarNames
		if len(invariantPattern.InputVarNames) > 0 {
			inputData := call.Data
			if len(inputData) > 4 {
				if isERC20Inv(checkerId) {
					method, err := ERC20Abi.MethodById(inputData)
					if err != nil {
						return err
					}
					inputValues, _ := method.Inputs.Unpack(inputData[4:])
					for index, arg := range method.Inputs {
						stateValue := getStateValue(arg, inputValues[index])
						if stateValue != nil {
							workerState.invariantState[arg.Name] = stateValue
						}
					}
				} else {
					for index, arg := range call.DataAbiValues.Method.Inputs {
						stateValue := getStateValue(arg, call.DataAbiValues.InputValues[index])
						if stateValue != nil {
							workerState.invariantState[arg.Name] = stateValue
						}
					}
				}
			}
		}

		if len(invariantPattern.PreStateVarNames) > 0 {
			err := t.getStateVariables(worker, "pre", invariantPattern.PreStateVarNames, call, contract)
			if err != nil {
				return err
			}
		}

		if len(invariantPattern.PostStateVarNames) > 0 {
			workerState.postStateVariablesFuncs = append(workerState.postStateVariablesFuncs, func(fw *FuzzerWorker) error {
				err := t.getStateVariables(fw, "post", invariantPattern.PostStateVarNames, call, contract)
				if err != nil {
					return err
				}
				return nil
			})
		}
	}
	return nil
}

func (t *InvariantCheckerProvider) getOriStateVariables(worker *FuzzerWorker, stateVarNames []string) {
	workerState := &t.workerStates[worker.WorkerIndex()]
	for _, name := range stateVarNames {
		if name == "balance" {
			workerState.invariantState["ori(balance)"] = worker.stateExtractor.getOriBalance(worker)
		} else {
			panic(fmt.Sprintf("not support %s in initInvariantOriState", name))
		}
	}
}

func (t *InvariantCheckerProvider) getInvariantPostState(worker *FuzzerWorker, callSequence calls.CallSequence) error {
	workerState := &t.workerStates[worker.WorkerIndex()]
	for _, f := range workerState.postStateVariablesFuncs {
		f(worker)
	}

	// for name, stateValue := range workerState.invariantState {
	// 	fmt.Println(name, stateValue.Value)
	// }
	// fmt.Println("----------")
	return nil
}

func (t *InvariantCheckerProvider) getStateVariables(worker *FuzzerWorker, stage string, stateVarNames []string, call *calls.CallMessage, contract *fuzzingTypes.Contract) error {
	workerState := &t.workerStates[worker.WorkerIndex()]
	// deal with stateVarNames
	for _, name := range stateVarNames {
		if _, ok := workerState.invariantState[fmt.Sprintf("%s(%s)", stage, name)]; ok {
			continue
		}
		if name == "balance" {
			balance, _, tokenBalanceMap := worker.stateExtractor.getBalance()
			for token := range tokenBalanceMap {
				workerState.invariantState[fmt.Sprintf("%s(token-%s)", stage, token.String())] = &invariant.StateValue{
					Value: new(big.Int).Set(tokenBalanceMap[token]),
					Type:  "uint256",
				}
			}
			workerState.invariantState[fmt.Sprintf("%s(%s)", stage, name)] = balance
		} else {
			var contractAddr common.Address
			var abi abi.ABI
			contractAddrStr := strings.Split(name, ".")[0]
			functionName := strings.Split(strings.Split(name, ".")[1], "(")[0]
			if contractAddrStr == "this" {
				contractAddr = *call.To
				abi = contract.CompiledContract().Abi
			} else {
				contractAddr = common.HexToAddress(contractAddrStr)
				abi = ERC20Abi
			}

			argsStr, found := strings.CutPrefix(name, fmt.Sprintf("%s.%s", contractAddrStr, functionName))
			if !found {
				return fmt.Errorf("fail to find argsStr in %s", name)
			}
			var argsStrList []string
			if argsStr != "()" {
				argsStrList = strings.Split(argsStr[1:len(argsStr)-1], ",")
			}
			var argList []interface{}
			if len(argsStrList) != len(abi.Methods[functionName].Inputs) {
				return fmt.Errorf("different length of argsStr and Inputs")
			}
			for index, arg := range abi.Methods[functionName].Inputs {
				argStrName := argsStrList[index]
				if stateValue, ok := workerState.invariantState[argStrName]; ok {
					argList = append(argList, stateValue.Value)
				} else {
					argList = append(argList, getArgumentFromString(arg, argStrName))
				}
			}
			data, err := abi.Pack(functionName, argList...)
			if err != nil {
				return fmt.Errorf("error in getInvariantPreState %v", err)
			}
			retVals, err := worker.stateExtractor.getStateVariablesFromViewMethod(worker, contractAddr, data, abi.Methods[functionName])
			if err != nil {
				return fmt.Errorf("error in getInvariantPreState %v", err)
			}

			if len(retVals) != 1 {
				return fmt.Errorf("not support the view method with more than one output in getInvariantPreState")
			}
			workerState.invariantState[fmt.Sprintf("%s(%s)", stage, name)] = retVals[0]
			// workerState.invariantState[fmt.Sprintf("%s(%s)", stage, name)] = getStateValue(abi.Methods[functionName].Outputs[0], retVals[0])
			// fmt.Println(getStateValue(abi.Methods[functionName].Outputs[0], retVals[0]))
		}
	}
	return nil
}
