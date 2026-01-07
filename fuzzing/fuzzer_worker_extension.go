package fuzzing

import (
	"fmt"
	"math/big"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/fuzzing/branchcoverage"
	"github.com/crytic/medusa/fuzzing/bugdetector"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/coverage"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/crytic/medusa/fuzzing/invariant"
	"github.com/crytic/medusa/fuzzing/storagewrite"
	"github.com/ethereum/go-ethereum/common"
	coreTypes "github.com/ethereum/go-ethereum/core/types"
)

func (fw *FuzzerWorker) initTestChain(testChain *chain.TestChain) {
	// If we have coverage-guided fuzzing enabled, create a tracer to collect coverage and connect it to the chain.
	if fw.fuzzer.config.Fuzzing.UseCoverageTracing() {
		fw.coverageTracer = coverage.NewCoverageTracer(fw.fuzzer.contractDefinitions)
		testChain.AddTracer(fw.coverageTracer, true, false)
	}

	if fw.fuzzer.config.Fuzzing.UseBranchCoverageTracing() {
		fw.branchCoverageTracer = branchcoverage.NewCoverageTracer(fw.fuzzer.contractDefinitions)
		testChain.AddTracer(fw.branchCoverageTracer, true, false)
	}

	if fw.fuzzer.config.Fuzzing.UseStorageWriteTracing() {
		fw.storageWriteTracer = storagewrite.NewStorageWriteTracer()
		testChain.AddTracer(fw.storageWriteTracer, true, false)
	}

	// If we have invariant-guided fuzzing enabled, create a tracer to collect invariant and connect it to the chain.
	if fw.fuzzer.config.Fuzzing.VariableRecoverConfig.TraceStorage && fw.fuzzer.config.Fuzzing.Testing.InvariantChecking.Enabled {
		fw.txTracer = invariant.NewTxTracer()
		fw.txTracer.SetContracts(fw.fuzzer.contractDefinitions, testChain.CheatCodeContracts())
		fw.txTracer.SetRecodingState([]common.Address{})
		testChain.AddTracer(fw.txTracer, true, false)
	}

	// for state tracing
	if fw.fuzzer.config.Fuzzing.UseStateTracing() {
		fw.stateTracer = &invariant.StateTracer{
			RecordingSLOAD:    true,
			RecordingSSTORE:   true,
			RecordingTransfer: true,
		}
		testChain.AddTracer(fw.stateTracer, true, false)
	}

	// attach bug detector
	if fw.fuzzer.config.Fuzzing.UseBugDetector() {
		fw.bugDetectorTracer = bugdetector.NewBugDetectorTracer(fw.fuzzer.helperContract, &fw.fuzzer.config.Fuzzing.BugDetectionConfig)
		testChain.AddTracer(fw.bugDetectorTracer, true, false)

		// set original ether for ether leaking
		if fw.fuzzer.config.Fuzzing.BugDetectionConfig.EtherLeaking {
			fw.bugDetectorTracer.SetOriginalEther(fw.fuzzer.config.Fuzzing.SenderAddressesBalances)
		}

		if fw.fuzzer.config.Fuzzing.BugDetectionConfig.EtherLeaking || fw.fuzzer.config.Fuzzing.BugDetectionConfig.UnsafeDelegateCall {
			var ads []common.Address
			for _, addr := range fw.fuzzer.config.Fuzzing.SenderAddresses {
				ads = append(ads, common.HexToAddress(addr))
			}
			if fw.fuzzer.helperContract != common.HexToAddress("0x") {
				ads = append(ads, fw.fuzzer.helperContract)
			}

			fw.bugDetectorTracer.SetAdversarialAddresses(ads)
		}
	}

	// for debug
	// testChain.AddTracer(executiontracer.NewExecutionTracer(fw.fuzzer.contractDefinitions, testChain.CheatCodeContracts()), true, false)

	if fw.fuzzer.config.Fuzzing.OnChainFuzzingConfig.IsOnChain {
		// copy accountState and attach accountState
		testChain.IsOnChain = true
		testChain.CacheAccountState = fw.fuzzer.fuzzerInitAccountState.initAccountState.DeepCopy()
		testChain.State().SetAccountState(testChain.CacheAccountState)
	}
}

func deployHelperContract(fuzzer *Fuzzer, testChain *chain.TestChain, block *types.Block, targetAddresses []common.Address) (error, *executiontracer.ExecutionTrace, common.Address) {
	helperContractAddress := common.Address{}
	// deploy helperContract
	args := make([]any, 0)
	var addressList []common.Address
	for _, targetAddress := range fuzzer.config.Fuzzing.OnChainFuzzingConfig.TargetAddresses {
		addressList = append(addressList, common.HexToAddress(targetAddress))
	}
	args = append(args, addressList)
	msgData, err := FuzzHelperContract.CompiledContract().GetDeploymentMessageData(args)
	if err != nil {
		return fmt.Errorf("initial contract deployment failed for contract \"%v\", error: %v", FuzzHelperContract.Name(), err), nil, helperContractAddress
	}

	initBalance := new(big.Int).Div(fuzzer.config.Fuzzing.SenderAddressesBalances[0], big.NewInt(2))
	msg := calls.NewCallMessage(fuzzer.senders[0], nil, 0, initBalance, fuzzer.config.Fuzzing.BlockGasLimit, nil, nil, nil, msgData)
	msg.FillFromTestChainProperties(testChain)
	err = testChain.PendingBlockAddTx(msg.ToCoreMessage())
	if err != nil {
		return err, nil, helperContractAddress
	}

	err = testChain.PendingBlockCommit()
	if err != nil {
		return err, nil, helperContractAddress
	}

	// Ensure our transaction succeeded and, if it did not, attach an execution trace to it and re-run it.
	// The execution trace will be returned so that it can be provided to the user for debugging
	if block.MessageResults[0].Receipt.Status != coreTypes.ReceiptStatusSuccessful {
		// Create a call sequence element to represent the failed contract deployment tx
		cse := calls.NewCallSequenceElement(nil, msg, 0, 0)
		cse.ChainReference = &calls.CallSequenceElementChainReference{
			Block:            block,
			TransactionIndex: len(block.Messages) - 1,
		}

		// Replay the execution trace for the failed contract deployment tx
		err = cse.AttachExecutionTrace(testChain, fuzzer.contractDefinitions)

		// Throw an error if execution tracing threw an error or the trace is nil
		if err != nil {
			return fmt.Errorf("failed to attach execution trace to failed contract deployment tx: %v", err), nil, helperContractAddress
		}
		if cse.ExecutionTrace == nil {
			return fmt.Errorf("contract deployment tx returned a failed status: %v", block.MessageResults[0].ExecutionResult.Err), nil, helperContractAddress
		}

		// Return the execution error and the execution trace
		return fmt.Errorf("contract deployment tx returned a failed status: %v", block.MessageResults[0].ExecutionResult.Err), cse.ExecutionTrace, helperContractAddress
	}

	return nil, nil, block.MessageResults[0].Receipt.ContractAddress
}
