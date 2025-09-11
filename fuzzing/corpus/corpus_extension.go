package corpus

import (
	"fmt"
	"math/big"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/fuzzing/branchcoverage"
	"github.com/crytic/medusa/fuzzing/bugdetector"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/coverage"
	"github.com/crytic/medusa/fuzzing/invariant"
	"github.com/crytic/medusa/fuzzing/storagewrite"
	"github.com/crytic/medusa/utils/randomutils"
	"github.com/ethereum/go-ethereum/common"
)

const capacity = 64
const queueSize = 1

func (c *Corpus) AddSeedWithStrategy(strategy string, seqHash common.Hash) {
	seedQueue, exists := c.seedQueues[strategy]
	if !exists {
		seedQueue = make([]common.Hash, 0)
	}
	seedQueue = append(seedQueue, seqHash)
	if len(seedQueue) >= capacity {
		oldSeqHash := seedQueue[0]
		c.mutationTargetSequenceChooser.RemoveByHash(oldSeqHash)
		seedQueue = seedQueue[1:]
	}
	c.seedQueues[strategy] = seedQueue
}

func (c *Corpus) AddSeed(label string, seqHash common.Hash) {
	seedQueue, exists := c.seedQueues[label]
	if !exists {
		seedQueue = make([]common.Hash, 0)
	}
	if len(seedQueue) >= queueSize {
		oldSeqHash := seedQueue[0]
		c.mutationTargetSequenceChooser.RemoveByHash(oldSeqHash)
		seedQueue = seedQueue[1:]
	}
	seedQueue = append(seedQueue, seqHash)
	c.seedQueues[label] = seedQueue
}

// CheckSequenceCoverageAndUpdate checks if the most recent call executed in the provided call sequence achieved
// coverage the Corpus did not with any of its call sequences. If it did, the call sequence is added to the corpus
// and the Corpus coverage maps are updated accordingly.
// Returns an error if one occurs.
func (c *Corpus) CheckSequenceStateCoverageAndUpdate(callSequence calls.CallSequence, mutationChooserWeight *big.Int, flushImmediately bool, isAddCallSequence bool, oldStateVariables, stateVariables map[string]*invariant.StateValue) error {
	// If we have coverage-guided fuzzing disabled or no calls in our sequence, there is nothing to do.
	if len(callSequence) == 0 {
		return nil
	}

	isNewScope := c.invariantMaps.UpdateState(stateVariables)
	isNewDirection, _ := c.invariantMaps.UpdateDirection(oldStateVariables, stateVariables)

	// If we had an increase in non-reverted or reverted coverage, we save the sequence.
	// Note: We only want to save the sequence once. We're most interested if it can be used for mutations first.
	if isAddCallSequence {
		if isNewScope || isNewDirection {
			// remove the revert calls
			newCallSequence := make(calls.CallSequence, 0)
			for _, callElement := range callSequence {
				if callElement.ChainReference.Block.MessageResults[callElement.ChainReference.TransactionIndex].ExecutionResult.Err == nil {
					newCallSequence = append(newCallSequence, callElement)
				}
			}
			// fmt.Println(newCallSequence[len(newCallSequence)-1].ChainReference.Block.MessageResults[newCallSequence[len(newCallSequence)-1].ChainReference.TransactionIndex].AdditionalResults["executionTracerDebug"].(*executiontracer.ExecutionTrace))
			// fmt.Printf("new seed, ori: %v, new: %v\n", len(callSequence), len(newCallSequence))
			// If we achieved new non-reverting coverage, save this sequence for mutation purposes.
			seqHash, err := c.addCallSequenceAndReturnSeqHash(c.mutableSequenceFiles, newCallSequence, true, mutationChooserWeight, flushImmediately)
			if err != nil {
				return err
			}
			if isNewDirection {
				c.AddSeedWithStrategy("new_direction", seqHash)
			}
			if isNewScope {
				c.AddSeedWithStrategy("new_scope", seqHash)
			}
		}
	}

	return nil
}

func (c *Corpus) CheckSequenceScopeInvariantAndUpdate(callSequence calls.CallSequence, mutationChooserWeight *big.Int, flushImmediately bool, isAddCallSequence bool, stateVariables map[string]*invariant.StateValue) (bool, error) {
	// If we have coverage-guided fuzzing disabled or no calls in our sequence, there is nothing to do.
	if len(callSequence) == 0 {
		return false, nil
	}

	isInteresting := c.invariantMaps.UpdateState(stateVariables)
	// if isNewScope {
	// c.invariantMaps.ShowScopeInvariants()
	// err = c.addCallSequence(c.mutableSequenceFiles, callSequence, true, mutationChooserWeight, flushImmediately)
	// if err != nil {
	// 	return isNewScope, err
	// }
	// }
	return isInteresting, nil
}

func (c *Corpus) AddSequence(callSequence calls.CallSequence, mutationChooserWeight *big.Int, flushImmediately bool) error {
	var err error
	err = c.addCallSequence(c.mutableSequenceFiles, callSequence, true, mutationChooserWeight, flushImmediately)
	if err != nil {
		return err
	}
	return nil
}

// Initialize initializes any runtime data needed for a Corpus on startup. Call sequences are replayed on the post-setup
// (deployment) test chain to calculate coverage, while resolving references to compiled contracts.
// Returns the active number of corpus items, total number of corpus items, or an error if one occurred. If an error
// is returned, then the corpus counts returned will always be zero.
func (c *Corpus) InitializeOnCahin(baseTestChain *chain.TestChain, contractDefinitions contracts.Contracts, deployedContractBytecodes []*types.DeployedContractBytecode) (int, int, error) {
	// Acquire our call sequences lock during the duration of this method.
	c.callSequencesLock.Lock()
	defer c.callSequencesLock.Unlock()

	// Initialize our call sequence structures.
	c.mutationTargetSequenceChooser = randomutils.NewWeightedRandomChooser[calls.CallSequence]()
	c.unexecutedCallSequences = make([]calls.CallSequence, 0)

	// Create a coverage tracer to track coverage across all blocks.
	c.coverageMaps = coverage.NewCoverageMaps()
	coverageTracer := coverage.NewCoverageTracer(contractDefinitions)

	c.branchCoverageMaps = branchcoverage.NewCoverageMaps()
	branchCoverageTracer := branchcoverage.NewCoverageTracer(contractDefinitions)

	// Create our structure and event listeners to track deployed contracts
	deployedContracts := make(map[common.Address]*contracts.Contract, 0)

	// Clone our test chain, adding listeners for contract deployment events from genesis.
	testChain, err := baseTestChain.Clone(func(newChain *chain.TestChain) error {
		// After genesis, prior to adding other blocks, we attach our coverage tracer
		if c.fuzzingConfig.UseCoverageTracing() {
			newChain.AddTracer(coverageTracer, true, false)
		}
		if c.fuzzingConfig.UseBranchCoverageTracing() {
			newChain.AddTracer(branchCoverageTracer, true, false)
		}

		// We also track any contract deployments, so we can resolve contract/method definitions for corpus call
		// sequences.
		newChain.Events.ContractDeploymentAddedEventEmitter.Subscribe(func(event chain.ContractDeploymentsAddedEvent) error {
			matchedContract := contractDefinitions.MatchBytecode(event.Contract.InitBytecode, event.Contract.RuntimeBytecode)
			if matchedContract != nil {
				deployedContracts[event.Contract.Address] = matchedContract
			}
			return nil
		})
		newChain.Events.ContractDeploymentRemovedEventEmitter.Subscribe(func(event chain.ContractDeploymentsRemovedEvent) error {
			delete(deployedContracts, event.Contract.Address)
			return nil
		})

		// for on-chain fuzzing
		for _, contract := range deployedContractBytecodes {
			newChain.Events.ContractDeploymentAddedEventEmitter.Publish(chain.ContractDeploymentsAddedEvent{
				Chain:             newChain,
				Contract:          contract,
				DynamicDeployment: false,
			})
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("failed to initialize coverage maps, base test chain cloning encountered error: %v", err)
	}

	// Set our coverage maps to those collected when replaying all blocks when cloning.
	c.coverageMaps = coverage.NewCoverageMaps()
	for _, block := range testChain.CommittedBlocks() {
		for _, messageResults := range block.MessageResults {
			covMaps := coverage.GetCoverageTracerResults(messageResults)
			_, _, covErr := c.coverageMaps.Update(covMaps)
			if covErr != nil {
				return 0, 0, err
			}
		}
	}

	// Next we replay every call sequence, checking its validity on this chain and measuring coverage. Valid sequences
	// are added to the corpus for mutations, re-execution, etc.
	//
	// The order of initializations here is important, as it determines the order of "unexecuted sequences" to replay
	// when the fuzzer's worker starts up. We want to replay test results first, so that other corpus items
	// do not trigger the same test failures instead.
	err = c.initializeSequences(c.testResultSequenceFiles, testChain, deployedContracts, false)
	if err != nil {
		return 0, 0, err
	}

	err = c.initializeSequences(c.mutableSequenceFiles, testChain, deployedContracts, true)
	if err != nil {
		return 0, 0, err
	}

	err = c.initializeSequences(c.immutableSequenceFiles, testChain, deployedContracts, false)
	if err != nil {
		return 0, 0, err
	}

	// Calculate corpus health metrics
	corpusSequencesTotal := c.mutableSequenceFiles.files.Len() + c.immutableSequenceFiles.files.Len() + c.testResultSequenceFiles.files.Len()
	corpusSequencesActive := len(c.unexecutedCallSequences)
	return corpusSequencesActive, corpusSequencesTotal, nil
}

// InvariantMaps exposes invariant details for all call sequences known to the corpus.
func (c *Corpus) InvariantMaps() *invariant.InvariantMaps {
	return c.invariantMaps
}

// addCallSequence adds a call sequence to the corpus in a given corpus directory.
// Returns an error, if one occurs.
func (c *Corpus) addCallSequenceAndReturnSeqHash(sequenceFiles *corpusDirectory[calls.CallSequence], sequence calls.CallSequence, useInMutations bool, mutationChooserWeight *big.Int, flushImmediately bool) (common.Hash, error) {
	// Acquire a thread lock during modification of call sequence lists.
	c.callSequencesLock.Lock()

	// Check if call sequence has been added before, if so, exit without any action.
	seqHash, err := sequence.Hash()
	if err != nil {
		return seqHash, err
	}

	// Verify no existing corpus item hash this same hash.
	// for _, existingSeq := range sequenceFiles.files {
	// 	// Calculate the existing sequence hash
	// 	existingSeqHash, err := existingSeq.data.Hash()
	// 	if err != nil {
	// 		c.callSequencesLock.Unlock()
	// 		return 0, err
	// 	}

	// 	// Verify it is unique, if it is not, we quit immediately to avoid duplicate sequences being added.
	// 	if bytes.Equal(existingSeqHash[:], seqHash[:]) {
	// 		c.callSequencesLock.Unlock()
	// 		return -1, nil
	// 	}
	// }
	fileName := fmt.Sprintf("%s.json", seqHash.Hex())
	if _, exists := sequenceFiles.files.Get(fileName); exists {
		c.callSequencesLock.Unlock()
		return seqHash, nil
	}

	// Update our corpus directory with the new entry.
	// fileName := fmt.Sprintf("%v-%v.json", time.Now().UnixNano(), uuid.New().String())
	err = sequenceFiles.addFile(fileName, sequence)
	if err != nil {
		return seqHash, err
	}

	// If we want to use this sequence in mutations and initialized a chooser, add our call sequence item to it.
	if useInMutations && c.mutationTargetSequenceChooser != nil {
		if mutationChooserWeight == nil {
			mutationChooserWeight = big.NewInt(1)
		}
		c.mutationTargetSequenceChooser.AddChoices(randomutils.NewWeightedRandomChoice[calls.CallSequence](sequence, mutationChooserWeight))
	}

	// Unlock now, as flushing will lock on its own.
	c.callSequencesLock.Unlock()

	// Flush changes to disk if requested.
	if flushImmediately {
		return seqHash, c.Flush()
	} else {
		return seqHash, nil
	}
}

// CheckSequenceMetricAndUpdate checks if the most recent call executed in the provided call sequence achieved
// any better metric the Corpus did not with any of its call sequences. If it did, the call sequence is added
// to the corpus and the Corpus global metric are updated accordingly.
// Returns an error if one occurs.
func (c *Corpus) CheckSequenceMetricAndUpdate(callSequence calls.CallSequence, mutationChooserWeight *big.Int, flushImmediately bool, isAddCallSequence bool) error {
	// If we have coverage-guided fuzzing disabled or no calls in our sequence, there is nothing to do.
	if len(callSequence) == 0 {
		return nil
	}

	// Obtain our coverage maps for our last call.
	lastCall := callSequence[len(callSequence)-1]
	lastCallChainReference := lastCall.ChainReference
	lastMessageResult := lastCallChainReference.Block.MessageResults[lastCallChainReference.TransactionIndex]
	//lastMessageCoverageMaps := coverage.GetCoverageTracerResults(lastMessageResult)

	// If we have none, because a coverage tracer wasn't attached when processing this call, we can stop.
	//if lastMessageCoverageMaps == nil {
	//	return nil
	//}

	updated := false
	revertedUpdated := false

	// Merge the coverage maps into our total coverage maps and check if we had an update.
	if c.fuzzingConfig.UseCoverageTracing() {
		coverageMaps := coverage.GetCoverageTracerResults(lastMessageResult)
		// Memory optimization: Remove them from the results now that we obtained them, to free memory later.
		//coverage.RemoveCoverageTracerResults(lastMessageResult)
		coverageUpdated, revertedCoverageUpdated, err := c.coverageMaps.Update(coverageMaps)
		if err != nil {
			return err
		}
		if c.fuzzingConfig.CoverageEnabled {
			updated = coverageUpdated || updated
			revertedUpdated = revertedCoverageUpdated || revertedUpdated
		}
	}

	if c.fuzzingConfig.UseBranchCoverageTracing() {
		branchCoverageMaps := branchcoverage.GetCoverageTracerResults(lastMessageResult)
		coverageUpdated, revertedCoverageUpdated, err := c.branchCoverageMaps.Update(branchCoverageMaps)
		if err != nil {
			return err
		}
		if c.fuzzingConfig.BranchCoverageEnabled {
			updated = coverageUpdated || updated
			revertedUpdated = revertedCoverageUpdated || revertedUpdated
		}
	}

	if c.fuzzingConfig.UseStorageWriteTracing() {
		storageWriteSet := storagewrite.GetStorageWriteTracerResults(lastMessageResult)
		storageWriteUpdated, revertedStorageWriteUpdated, err := c.storageWriteSet.Update(storageWriteSet)
		if err != nil {
			return err
		}
		if c.fuzzingConfig.StorageWriteEnabled {
			updated = storageWriteUpdated || updated
			revertedUpdated = revertedStorageWriteUpdated || revertedUpdated
		}
	}

	if c.fuzzingConfig.UseBugDetector() {
		bugMap := bugdetector.GetBugDetectorTracerResults(lastMessageResult)
		_, err := c.bugMap.Update(bugMap)
		if err != nil {
			return err
		}
	}

	// If we had an increase in non-reverted or reverted coverage, we save the sequence.
	// Note: We only want to save the sequence once. We're most interested if it can be used for mutations first.
	if isAddCallSequence {
		if updated {
			// If we achieved new non-reverting coverage, save this sequence for mutation purposes.
			err := c.addCallSequence(c.mutableSequenceFiles, callSequence, true, mutationChooserWeight, flushImmediately)
			if err != nil {
				return err
			}
		} else if revertedUpdated {
			// If we did not achieve new successful coverage, but achieved an increase in reverted coverage, save this
			// sequence for non-mutation purposes.
			err := c.addCallSequence(c.immutableSequenceFiles, callSequence, false, mutationChooserWeight, flushImmediately)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// RemoveTracerResults Memory optimization: Remove tracer results from the call sequence, to free memory later.
func (c *Corpus) RemoveTracerResults(callSequence calls.CallSequence) {
	// If we have coverage-guided fuzzing disabled or no calls in our sequence, there is nothing to do.
	if len(callSequence) == 0 {
		return
	}

	// Obtain our coverage maps for our last call.
	lastCall := callSequence[len(callSequence)-1]
	lastCallChainReference := lastCall.ChainReference
	lastMessageResult := lastCallChainReference.Block.MessageResults[lastCallChainReference.TransactionIndex]

	if c.fuzzingConfig.UseCoverageTracing() {
		coverage.RemoveCoverageTracerResults(lastMessageResult)
	}

	if c.fuzzingConfig.UseBranchCoverageTracing() {
		branchcoverage.RemoveCoverageTracerResults(lastMessageResult)
	}

	if c.fuzzingConfig.UseStorageWriteTracing() {
		storagewrite.RemoveStorageWriteTracerResults(lastMessageResult)
	}
}
