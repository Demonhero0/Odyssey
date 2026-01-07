package fuzzing

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/compilation/platforms"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/config"
	fuzzerTypes "github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/corpus"
	"github.com/crytic/medusa/fuzzing/coverage"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/crytic/medusa/fuzzing/invariant"
	"github.com/crytic/medusa/fuzzing/valuegeneration"
	"github.com/crytic/medusa/logging"
	"github.com/crytic/medusa/logging/colors"
	"github.com/crytic/medusa/utils"
	"github.com/crytic/medusa/utils/rpc"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
)

type FuzzerInitAccountState struct {
	initAccountState     *state.AccountState
	initAccountStateLock sync.Mutex
}

// NewFuzzer returns an instance of a new Fuzzer provided a project configuration, or an error if one is encountered
// while initializing the code.
func NewFuzzerOnCahin(config config.ProjectConfig) (*Fuzzer, error) {
	// Disable colors if requested
	if config.Logging.NoColor {
		colors.DisableColor()
	}

	// Create the global logger and add stdout as an unstructured output stream
	// Note that we are not using the project config's log level because we have not validated it yet
	logging.GlobalLogger = logging.NewLogger(config.Logging.Level)
	logging.GlobalLogger.AddWriter(os.Stdout, logging.UNSTRUCTURED, !config.Logging.NoColor)

	// If the log directory is a non-empty string, create a file for unstructured, un-colorized file logging
	if config.Logging.LogDirectory != "" {
		// Filename will be the "log-current_unix_timestamp.log"
		filename := "log-" + strconv.FormatInt(time.Now().Unix(), 10) + ".log"
		// Create the file
		file, err := utils.CreateFile(config.Logging.LogDirectory, filename)
		if err != nil {
			logging.GlobalLogger.Error("Failed to create log file", err)
			return nil, err
		}
		logging.GlobalLogger.AddWriter(file, logging.UNSTRUCTURED, false)
	}

	// Validate our provided config
	err := config.Validate()
	if err != nil {
		logging.GlobalLogger.Error("Invalid configuration", err)
		return nil, err
	}

	// Update the log level of the global logger now
	logging.GlobalLogger.SetLevel(config.Logging.Level)

	// Get the fuzzer's custom sub-logger
	logger := logging.GlobalLogger.NewSubLogger("module", "fuzzer")

	// Parse the senders addresses from our account config.
	senders, err := utils.HexStringsToAddresses(config.Fuzzing.SenderAddresses)
	if err != nil {
		logger.Error("Invalid sender address(es)", err)
		return nil, err
	}

	// Parse the deployer address from our account config
	deployer, err := utils.HexStringToAddress(config.Fuzzing.DeployerAddress)
	if err != nil {
		logger.Error("Invalid deployer address", err)
		return nil, err
	}

	// Parse the senders addresses from our account config.
	contracts, err := utils.HexStringsToAddresses(config.Fuzzing.OnChainFuzzingConfig.TargetAddresses)
	if err != nil {
		logger.Error("Invalid contract address(es)", err)
		return nil, err
	}

	// Create and return our fuzzing instance.
	fuzzer := &Fuzzer{
		config:              config,
		senders:             senders,
		deployer:            deployer,
		baseValueSet:        valuegeneration.NewValueSet(),
		contractDefinitions: make(fuzzerTypes.Contracts, 0),
		testCases:           make([]TestCase, 0),
		testCasesFinished:   make(map[string]TestCase),
		Hooks: FuzzerHooks{
			NewCallSequenceGeneratorConfigFunc: defaultCallSequenceGeneratorConfigFunc,
			NewShrinkingValueMutatorFunc:       defaultShrinkingValueMutatorFunc,
			ChainSetupFunc:                     chainSetupFromOnChain,
			CallSequenceTestFuncs:              make([]CallSequenceTestFunc, 0),
		},
		logger:                  logger,
		proxyContractMap:        make(map[common.Address]common.Address),
		targetContractAddresses: contracts,
	}

	// Add our sender and deployer addresses to the base value set for the value generator, so they will be used as
	// address arguments in fuzzing campaigns.
	fuzzer.baseValueSet.AddAddress(fuzzer.deployer)
	for _, sender := range fuzzer.senders {
		fuzzer.baseValueSet.AddAddress(sender)
	}

	// init the node url and initAccountState
	rpc.Provider = rpc.NodeProvider{
		NodeURL: fuzzer.config.Fuzzing.OnChainFuzzingConfig.NodeUrl,
	}
	fuzzer.fuzzerInitAccountState = FuzzerInitAccountState{
		initAccountState: state.NewAccountState(true, &rpc.Provider, int64(fuzzer.config.Fuzzing.OnChainFuzzingConfig.BlockNumber)),
	}

	// for deploying test contract
	if fuzzer.config.Fuzzing.OnChainFuzzingConfig.InitialStatePath != "" {
		err = fuzzer.loadInitialState()
		if err != nil {
			return nil, fmt.Errorf("error in loading initial state:%v", err)
		}
	}

	// crawl target contracts
	for _, targetAddress := range fuzzer.config.Fuzzing.OnChainFuzzingConfig.TargetAddresses {
		targetAddress = strings.ToLower(targetAddress)
		fuzzer.logger.Info(fmt.Sprintf("Initialzing contract of target %s", targetAddress), colors.Reset)
		contractInfo, err := fuzzer.handleOnChainAddress(targetAddress)
		if err != nil {
			return nil, err
		}

		fuzzer.proxyContractMap[common.HexToAddress(targetAddress)] = common.HexToAddress(targetAddress)
		if contractInfo.Proxy && contractInfo.Implementation != "" {
			fuzzer.logger.Info(fmt.Sprintf("-> Initialzing contract of implementation %s", strings.ToLower(contractInfo.Implementation)), colors.Reset)
			_, err := fuzzer.handleOnChainAddress(contractInfo.Implementation)
			if err != nil {
				return nil, err
			}
			fuzzer.proxyContractMap[common.HexToAddress(targetAddress)] = common.HexToAddress(contractInfo.Implementation)
		}
	}

	if fuzzer.config.Fuzzing.Testing.InvariantChecking.Enabled {
		attachInvariantTestCaseProvider(fuzzer)
	}

	// attach helper contract
	attachHelperContract(fuzzer)

	return fuzzer, nil
}

func attachHelperContract(f *Fuzzer) {
	f.contractDefinitions = append(f.contractDefinitions, fuzzerTypes.NewContract("ERC1820Registry", ERC1820RegistryAddr.String(), ERC1820RegistryContract.CompiledContract(), nil))
	f.contractDefinitions = append(f.contractDefinitions, fuzzerTypes.NewContract("FuzzHelperContract", "FuzzHelperContract", FuzzHelperContract.CompiledContract(), nil))
}

func (f *Fuzzer) handleOnChainAddress(targetAddress string) (contractInfo *rpc.ContractInfo, err error) {
	targetAddress = strings.ToLower(targetAddress)
	contractInfo, err = f.getContractInfo(targetAddress)
	if err != nil {
		return nil, err
	}
	// if _, ok := contractInfoMap[targetAddress]; ok {
	// 	contractInfo = contractInfoMap[targetAddress]
	// } else {
	// 	// abiString, err := rpc.GetContractABI(targetAddress, f.config.Fuzzing.OnChainFuzzingConfig.EtherscanApiKey)
	// 	contractInfoList, err := rpc.GetContractSourceCode(targetAddress, "", f.config.Fuzzing.OnChainFuzzingConfig.EtherscanApiKey)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	if len(contractInfoList) != 1 {
	// 		return nil, fmt.Errorf("cannot handle more than one contractInfo")
	// 	}

	// 	contractInfo = contractInfoList[0]
	// 	contractInfoMap[targetAddress] = contractInfo
	// }
	if contractInfo.Abi == "Contract source code not verified" {
		f.logger.Warn(fmt.Sprintf("Failed to get the ABI of contract %s", targetAddress))
		contractInfo.Abi = "[]"
	}

	contractAbi, err := abi.JSON(strings.NewReader(contractInfo.Abi))
	if err != nil {
		return nil, fmt.Errorf("ABI Parser error: %v", err)
	}

	deployedBytecode, err := f.fuzzerInitAccountState.initAccountState.GetCode(common.HexToAddress(targetAddress))
	if err != nil {
		f.logger.Error(fmt.Sprintf("Failed to crawl deployedBytecode in %s", targetAddress))
		return nil, err
	}

	if len(deployedBytecode) == 0 {
		f.logger.Warn(fmt.Sprintf("The deployedBytecode in %s is empty", targetAddress))
		// return nil, nil
	}

	contract := compilationTypes.CompiledContract{
		Abi:             contractAbi,
		RuntimeBytecode: deployedBytecode,
	}
	contractDefinition := fuzzerTypes.NewContract(contractInfo.ContractName, targetAddress, &contract, nil)
	f.contractDefinitions = append(f.contractDefinitions, contractDefinition)
	return contractInfo, nil
}

func (f *Fuzzer) handleOnChainAddressWithCompilation(targetAddress string) error {
	var err error

	// compile contract with crytic-compile
	etherscanExportPath := f.config.Fuzzing.OnChainFuzzingConfig.CacheContractPath + "/" + targetAddress
	cryticCompilationConfig := platforms.CryticCompilationConfig{
		Target:          targetAddress,
		ExportDirectory: etherscanExportPath,
		// Args:            []string{"--etherscan-apikey", f.config.Fuzzing.OnChainFuzzingConfig.EtherscanApiKey, "--etherscan-export-directory", etherscanExportPath, "--solc-args", fmt.Sprintf("\"--allow-paths %s\"", etherscanExportPath)},
		Args: []string{"--etherscan-apikey", f.config.Fuzzing.OnChainFuzzingConfig.EtherscanApiKey, "--etherscan-export-directory", etherscanExportPath},
	}
	// check exist
	var compilations []compilationTypes.Compilation
	compilations, err = cryticCompilationConfig.CheckAndLoadExistCompilations()
	if err != nil {
		return fmt.Errorf("error in load existing compilations:%v", err)
	}
	if len(compilations) == 0 {
		// change path
		oriPath, _ := os.Getwd()
		os.Chdir(filepath.Dir(etherscanExportPath))
		compilations, _, err = cryticCompilationConfig.Compile()
		if err != nil {
			f.logger.Error("Failed to compile target", err)
			return err
		}
		os.Chdir(oriPath)
	} else {
		f.logger.Info(fmt.Sprintf("Using exisitng combined_solc.json of target %s ", targetAddress), colors.Reset)
	}

	deployedBytecode, err := f.fuzzerInitAccountState.initAccountState.GetCode(common.HexToAddress(targetAddress))
	if err != nil {
		f.logger.Error(fmt.Sprintf("Failed to crawl deployedBytecode in %s", targetAddress))
		return err
	}

	if len(deployedBytecode) == 0 {
		f.logger.Error(fmt.Sprintf("The deployedBytecode in %s is empty", targetAddress))
		return fmt.Errorf("the deployedBytecode in %s is empty", targetAddress)
	}

	// find contractName and mainContractPath
	var contractRootPath string
	for _, compilation := range compilations {
		var mainContractName string
		// find main contract
		if len(compilation.SourceList) > 0 {
			source := compilation.SourceList[0]
			sliceParts := strings.Split(source, "/")
			for _, part := range sliceParts {
				tmpStr, existPrefix := strings.CutPrefix(part, targetAddress+"-")
				if existPrefix {
					// check
					tmpStr, existSuffix := strings.CutSuffix(tmpStr, ".sol")
					mainContractName = tmpStr
					if existSuffix {
						contractRootPath = etherscanExportPath
					} else {
						contractRootPath = fmt.Sprintf("%s/%s-%s", etherscanExportPath, targetAddress, mainContractName)
					}
					break
				}
			}
		}
		for source, compiledSource := range compilation.Sources {
			contracts := compiledSource.Contracts
			for contractName := range contracts {
				// findout the target contract
				if contractName == mainContractName {

					// replace the RuntimeBytecode
					contract := compiledSource.Contracts[contractName]
					contract.RuntimeBytecode = deployedBytecode
					compiledSource.Contracts[contractName] = contract

					mainContractPath := source
					// for invariant, using slither to obtain storage_layout
					if f.config.Fuzzing.VariableRecoverConfig.TraceStorage {
						logStr := fmt.Sprintf("Extract storage layout of target %s", targetAddress)
						isExist, err := invariant.InitStorageExtractor(etherscanExportPath, mainContractPath, contractRootPath, f.config.Fuzzing.VariableRecoverConfig.SlitherScriptPath)
						if isExist {
							logStr = logStr + " (Using existing storage layout)"
						}
						f.logger.Info(logStr, colors.Reset)
						if err != nil {
							f.logger.Error("Failed to extract storage layout", err)
							return err
						}
					}
				}
			}
		}
	}
	f.AddCompilationTargets(compilations)
	return nil
}

// Start begins a fuzzing operation on the provided project configuration. This operation will not return until an error
// is encountered or the fuzzing operation has completed. Its execution can be cancelled using the Stop method.
// Returns an error if one is encountered.
func (f *Fuzzer) StartOnChain() error {
	// Define our variable to catch errors
	var err error

	// While we're fuzzing, we'll want to have an initialized random provider.
	f.randomProvider = rand.New(rand.NewSource(time.Now().UnixNano()))

	// Create our running context (allows us to cancel across threads)
	f.ctx, f.ctxCancelFunc = context.WithCancel(context.Background())

	// If we set a timeout, create the timeout context now, as we're about to begin fuzzing.
	if f.config.Fuzzing.Timeout > 0 {
		f.logger.Info("Running with a timeout of ", colors.Bold, f.config.Fuzzing.Timeout, " seconds")
		f.ctx, f.ctxCancelFunc = context.WithTimeout(f.ctx, time.Duration(f.config.Fuzzing.Timeout)*time.Second)
	}

	// Set up the corpus
	f.logger.Info("Initializing corpus")
	f.corpus, err = corpus.NewCorpus(f.config.Fuzzing.CorpusDirectory, &f.config.Fuzzing)
	if err != nil {
		f.logger.Error("Failed to create the corpus", err)
		return err
	}

	// for state guide
	if f.config.Fuzzing.UseStateGuided() {
		f.corpus.InvariantMaps().InitInvariantMaps(
			f.config.Fuzzing.StateGuidedConfig.EnabledNewScope,
			// f.config.Fuzzing.StateGuidedConfig.EnabledStateConstruction,
			f.config.Fuzzing.StateGuidedConfig.EnabledStateDivision,
			f.config.Fuzzing.StateGuidedConfig.EnabledStateDirection,
			f.config.Fuzzing.StateGuidedConfig.InitUpdateBar,
			f.config.Fuzzing.StateGuidedConfig.DivisionPartNumber,
		)
	}

	// Initialize our metrics and valueGenerator.
	f.metrics = newFuzzerMetrics(f.config.Fuzzing.Workers)

	// Initialize our test cases and providers
	f.testCasesLock.Lock()
	f.testCases = make([]TestCase, 0)
	f.testCasesFinished = make(map[string]TestCase)
	f.testCasesLock.Unlock()

	// Create our test chain
	baseTestChain, deployedContractBytecodes, err := f.createTestChainOnChain()
	if err != nil {
		f.logger.Error("Failed to create the test chain", err)
		return err
	}

	// Set it up with our deployment/setup strategy defined by the fuzzer.
	f.logger.Info("Setting up base chain")
	err, trace := f.Hooks.ChainSetupFunc(f, baseTestChain)
	if err != nil {
		if trace != nil {
			f.logger.Error("Failed to initialize the test chain", err, errors.New(trace.Log().ColorString()))
		} else {
			f.logger.Error("Failed to initialize the test chain", err)
		}
		return err
	}

	// Initialize our coverage maps by measuring the coverage we get from the corpus.
	var corpusActiveSequences, corpusTotalSequences int
	f.logger.Info("Initializing and validating corpus call sequences")
	corpusActiveSequences, corpusTotalSequences, err = f.corpus.InitializeOnCahin(baseTestChain, f.contractDefinitions, deployedContractBytecodes)
	if err != nil {
		f.logger.Error("Failed to initialize the corpus", err)
		return err
	}

	// err = f.attachCallSequenceToCorpus(baseTestChain, deployedContractBytecodes)
	// if err != nil {
	// 	f.logger.Error("Falied to attach TokenSwap To Corpus", err)
	// 	return err
	// }

	// Log corpus health statistics, if we have any existing sequences.
	if corpusTotalSequences > 0 {
		f.logger.Info(
			colors.Bold, "corpus: ", colors.Reset,
			"health: ", colors.Bold, int(float32(corpusActiveSequences)/float32(corpusTotalSequences)*100.0), "%", colors.Reset, ", ",
			"sequences: ", colors.Bold, corpusTotalSequences, " (", corpusActiveSequences, " valid, ", corpusTotalSequences-corpusActiveSequences, " invalid)", colors.Reset,
		)
	}

	// Log the start of our fuzzing campaign.
	f.logger.Info("Fuzzing with ", colors.Bold, f.config.Fuzzing.Workers, colors.Reset, " workers")

	// Start our printing loop now that we're about to begin fuzzing.
	go f.printMetricsLoop()

	if f.config.Fuzzing.MetricLogConfig.Enabled {
		go f.logMetricsTimeLoop()

		f.Events.WorkerCreated.Subscribe(func(event FuzzerWorkerCreatedEvent) error {
			event.Worker.Events.CallSequenceTested.Subscribe(func(event FuzzerWorkerCallSequenceTestedEvent) error {
				f.logMetricsSequenceTestedSubscriber()
				return nil
			})
			return nil
		})
	}

	// Publish a fuzzer starting event.
	err = f.Events.FuzzerStarting.Publish(FuzzerStartingEvent{Fuzzer: f})
	if err != nil {
		f.logger.Error("FuzzerStarting event subscriber returned an error", err)
		return err
	}

	// If StopOnNoTests is true and there are no test cases, then throw an error
	if f.config.Fuzzing.Testing.StopOnNoTests && len(f.testCases) == 0 {
		err = fmt.Errorf("no tests of any kind (assertion/property/optimization/custom) have been identified for fuzzing")
		f.logger.Error("Failed to start fuzzer", err)
		return err
	}

	f.startTime = time.Now()

	// Run the main worker loop
	err = f.spawnWorkersLoop(baseTestChain)
	if err != nil {
		f.logger.Error("Encountered an error in the main fuzzing loop", err)
	}

	// NOTE: After this point, we capture errors but do not return immediately, as we want to exit gracefully.

	// If we have coverage enabled and a corpus directory set, write the corpus. We do this even if we had a
	// previous error, as we don't want to lose corpus entries.
	if f.config.Fuzzing.CoverageEnabled {
		corpusFlushErr := f.corpus.Flush()
		if err == nil && corpusFlushErr != nil {
			err = corpusFlushErr
			f.logger.Info("Failed to flush the corpus", err)
		}
	}

	// Publish a fuzzer stopping event.
	fuzzerStoppingErr := f.Events.FuzzerStopping.Publish(FuzzerStoppingEvent{Fuzzer: f, err: err})
	if err == nil && fuzzerStoppingErr != nil {
		err = fuzzerStoppingErr
		f.logger.Error("FuzzerStopping event subscriber returned an error", err)
	}

	// Print our results on exit.
	f.printExitingResults()

	// Finally, generate our coverage report if we have set a valid corpus directory.
	if err == nil && f.config.Fuzzing.CorpusDirectory != "" {
		coverageReportPath := filepath.Join(f.config.Fuzzing.CorpusDirectory, "coverage_report.html")
		err = coverage.GenerateReport(f.compilations, f.corpus.CoverageMaps(), coverageReportPath)
		f.logger.Info("Coverage report saved to file: ", colors.Bold, coverageReportPath, colors.Reset)
	}

	// Return any encountered error.
	return err
}

// createTestChain creates a test chain with the account balance allocations specified by the config.
func (f *Fuzzer) createTestChainOnChain() (*chain.TestChain, []*types.DeployedContractBytecode, error) {
	// Create our genesis allocations.
	// NOTE: Sharing GenesisAlloc between chains will result in some accounts not being funded for some reason.
	genesisAlloc := make(core.GenesisAlloc)

	// Fund our deployer address in the genesis block
	initBalance := new(big.Int).Div(abi.MaxInt256, big.NewInt(2)) // TODO: make this configurable
	genesisAlloc[f.deployer] = core.GenesisAccount{
		Balance: initBalance,
	}
	f.fuzzerInitAccountState.initAccountState.InitAccountState.UpdateTouchedBalance(f.deployer, initBalance)
	f.fuzzerInitAccountState.initAccountState.TraceAccountState.UpdateTouchedBalance(f.deployer, initBalance)

	// Fund all of our sender addresses in the genesis block
	// initBalance := new(big.Int).Div(abi.MaxInt256, big.NewInt(2))         // TODO: make this configurable
	// initBalance, _ := new(big.Int).SetString("100000000000000000000", 10) // 10 ** 20
	for index, sender := range f.senders {
		if index < len(f.config.Fuzzing.SenderAddressesBalances) {
			initBalance := new(big.Int).Set(f.config.Fuzzing.SenderAddressesBalances[index])

			genesisAlloc[sender] = core.GenesisAccount{
				Balance: initBalance,
			}
			f.fuzzerInitAccountState.initAccountState.InitAccountState.UpdateTouchedBalance(sender, initBalance)
			f.fuzzerInitAccountState.initAccountState.TraceAccountState.UpdateTouchedBalance(sender, initBalance)
		}
	}

	for address, utilAddress := range utilAddressMap {
		genesisAlloc[address] = core.GenesisAccount{
			Balance: utilAddress.Balance,
			Code:    utilAddress.Code,
		}
		f.fuzzerInitAccountState.initAccountState.InitAccountState.UpdateTouchedBalance(address, utilAddress.Balance)
		f.fuzzerInitAccountState.initAccountState.TraceAccountState.UpdateTouchedBalance(address, utilAddress.Balance)
		f.fuzzerInitAccountState.initAccountState.InitAccountState.UpdateTouchedCode(address, utilAddress.Code)
		f.fuzzerInitAccountState.initAccountState.TraceAccountState.UpdateTouchedCode(address, utilAddress.Code)
	}

	// Create our test chain with our basic allocations and passed medusa's chain configuration
	testChain, err := chain.NewTestChain(genesisAlloc, &f.config.Fuzzing.TestChainConfig)

	// copy accountState and attach accountState
	testChain.IsOnChain = true
	testChain.CacheAccountState = f.fuzzerInitAccountState.initAccountState.DeepCopy()
	testChain.State().SetAccountState(testChain.CacheAccountState)

	var contracts []*types.DeployedContractBytecode
	for _, addr := range f.config.Fuzzing.OnChainFuzzingConfig.TargetAddresses {
		address := common.HexToAddress(addr)
		contracts = append(contracts, &types.DeployedContractBytecode{
			Address:         address,
			RuntimeBytecode: f.fuzzerInitAccountState.initAccountState.InitAccountState.GetCode(address),
		})
	}

	if len(f.config.Fuzzing.OnChainFuzzingConfig.TargetAddresses) == 0 {
		return nil, contracts, fmt.Errorf("missing target addresses (update fuzzing.OnChainFuzzingConfig.TargetAddresses in the project config " +
			" or use the --target-addresses CLI flag)")
	}

	// Set our block gas limit
	testChain.BlockGasLimit = f.config.Fuzzing.BlockGasLimit
	return testChain, contracts, err
}

// chainSetupFromOnChain is a TestChainSetupFunc which sets up the base test chain state by forking from on-chain envirionment.
func chainSetupFromOnChain(fuzzer *Fuzzer, testChain *chain.TestChain) (error, *executiontracer.ExecutionTrace) {
	blockNumber := int64(fuzzer.config.Fuzzing.OnChainFuzzingConfig.BlockNumber)
	blockInfo, err := rpc.Provider.GetBlockByNumber(big.NewInt(blockNumber))
	if err != nil {
		fuzzer.logger.Error(fmt.Sprintf("Failed to crawl block in %d", blockNumber))
	}

	// create a new block to simulate the on-chain environment
	block, err := testChain.PendingBlockCreateWithParameters(uint64(blockNumber), blockInfo.Header().Time, nil)
	if err != nil {
		return err, nil
	}

	// for debug
	// testChain.AddTracer(executiontracer.NewExecutionTracer(fuzzer.contractDefinitions, testChain.CheatCodeContracts()), true, false)

	if fuzzer.config.Fuzzing.UseHelperContract() {
		// deploy helperContract
		var executionTrace *executiontracer.ExecutionTrace
		err, executionTrace, FuzzHelperContractAddr = deployHelperContract(fuzzer, testChain, block, []common.Address{})
		if err != nil {
			return err, executionTrace
		}

		fuzzer.baseValueSet.AddAddress(FuzzHelperContractAddr)
		fuzzer.helperContract = FuzzHelperContractAddr
	}

	for _, tokenAddress := range fuzzer.config.Fuzzing.OnChainFuzzingConfig.TargetAddresses {
		token := common.HexToAddress(tokenAddress)
		for _, targetAddress := range fuzzer.config.Fuzzing.OnChainFuzzingConfig.TargetAddresses {
			data, err := ERC20Abi.Pack("approve", common.HexToAddress(targetAddress), abi.MaxInt256)
			if err != nil {
				return err, nil
			}
			msg := calls.NewCallMessage(fuzzer.senders[0], &token, 0, big.NewInt(0), fuzzer.config.Fuzzing.TransactionGasLimit, nil, nil, nil, data)
			msg.FillFromTestChainProperties(testChain)

			_, err = testChain.PendingBlockCreate()
			if err != nil {
				return err, nil
			}
			testChain.PendingBlockAddTx(msg.ToCoreMessage())
			testChain.PendingBlockCommit()

			// for _, messageResult := range tmpBlock.MessageResults {
			// 	executionTrace := messageResult.AdditionalResults["executionTracerDebug"].(*executiontracer.ExecutionTrace)
			// 	fmt.Print(executionTrace.Log())
			// }
		}
	}

	return nil, nil
}

func (fw *FuzzerWorker) beforeRun() error {
	if fw.fuzzer.config.Fuzzing.OnChainFuzzingConfig.IsOnChain {
		// for sync the initAccountState with traceAccountState
		fw.chain.CacheAccountState.InitAccountState = fw.chain.CacheAccountState.TraceAccountState.DeepCopy()

		// Emit on-chain contracts deployment
		for _, targetAddress := range fw.fuzzer.config.Fuzzing.OnChainFuzzingConfig.TargetAddresses {
			// runtimeBytecode := initializedChain.State().GetCode(common.HexToAddress(targetAddress))
			runtimeBytecode, err := fw.chain.CacheAccountState.GetCode(common.HexToAddress(targetAddress))
			if err != nil {
				return fmt.Errorf("failed to crawl deployedBytecode in %s : %v", targetAddress, err)
			}
			if len(runtimeBytecode) > 0 {
				fw.chain.Events.ContractDeploymentAddedEventEmitter.Publish(chain.ContractDeploymentsAddedEvent{
					Chain: fw.chain,
					Contract: &types.DeployedContractBytecode{
						Address:         common.HexToAddress(targetAddress),
						RuntimeBytecode: runtimeBytecode,
					},
					DynamicDeployment: false,
				})
			} else {
				fw.fuzzer.logger.Warn(fmt.Sprintf("the on-chain contract in %s is empty", strings.ToLower(targetAddress)))
				// return fmt.Errorf()
				return nil
			}
		}
	}

	// init state variables
	if fw.fuzzer.config.Fuzzing.UseStateTracing() {
		err := fw.stateExtractor.initStateVariablesFromViewMethods()
		if err != nil {
			return err
		}
	}
	return nil
}
