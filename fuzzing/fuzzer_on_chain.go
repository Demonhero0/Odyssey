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
	"github.com/crytic/medusa/fuzzing/branchcoverage"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/config"
	fuzzerTypes "github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/corpus"
	"github.com/crytic/medusa/fuzzing/coverage"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/crytic/medusa/fuzzing/invariant"
	"github.com/crytic/medusa/fuzzing/storagewrite"
	"github.com/crytic/medusa/fuzzing/valuegeneration"
	"github.com/crytic/medusa/logging"
	"github.com/crytic/medusa/logging/colors"
	"github.com/crytic/medusa/utils"
	"github.com/crytic/medusa/utils/rpc"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	coreTypes "github.com/ethereum/go-ethereum/core/types"
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

	if config.Fuzzing.Testing.ContractCallConfig.EnabledContractCall {
		fuzzer.baseValueSet.AddAddress(FuzzHelperContractAddr)
	}

	// init the node url and initAccountState
	rpc.Provider = rpc.NodeProvider{
		NodeURL: fuzzer.config.Fuzzing.OnChainFuzzingConfig.NodeUrl,
	}
	fuzzer.fuzzerInitAccountState = FuzzerInitAccountState{
		initAccountState: state.NewAccountState(true, &rpc.Provider, int64(fuzzer.config.Fuzzing.OnChainFuzzingConfig.BlockNumber)),
	}

	// compile helpercontract and util contract
	// if fuzzer.config.Fuzzing.UseHelperContract() {
	// 	compilation := helpercontracts.InitHelperContractCompilation()
	// 	// Compile the targets specified in the compilation config
	// 	fuzzer.logger.Info("Compiling helpercontract with ", colors.Bold, fuzzer.config.Compilation.Platform, colors.Reset)
	// 	compilations, _, err := compilation.Compile()
	// 	if err != nil {
	// 		fuzzer.logger.Error("Failed to compile helpercontract", err)
	// 		return nil, err
	// 	}

	// 	// Loop for each contract in each compilation and deploy it to the test node.
	// 	for i := 0; i < len(compilations); i++ {
	// 		// Add our compilation to the list and get a reference to it.
	// 		fuzzer.compilations = append(fuzzer.compilations, compilations[i])
	// 		compilation := &fuzzer.compilations[len(fuzzer.compilations)-1]

	// 		// Loop for each source
	// 		for sourcePath, source := range compilation.Sources {
	// 			// Loop for every contract and register it in our contract definitions
	// 			for contractName := range source.Contracts {
	// 				contract := source.Contracts[contractName]
	// 				contractDefinition := fuzzerTypes.NewContract(contractName, sourcePath, &contract, compilation)
	// 				fuzzer.contractDefinitions = append(fuzzer.contractDefinitions, contractDefinition)
	// 			}
	// 		}

	// 		// Cache all of our source code if it hasn't been already.
	// 		err := compilation.CacheSourceCode()
	// 		if err != nil {
	// 			fuzzer.logger.Warn("Failed to cache compilation source file data", err)
	// 		}
	// 	}
	// }

	// for deploying test contract
	if fuzzer.config.Fuzzing.OnChainFuzzingConfig.InitialStatePath != "" {
		err = fuzzer.loadInitialState()
		if err != nil {
			return nil, fmt.Errorf("error in loading initial state:%v", err)
		}
	}

	// load proxyContractMap
	// cacheData, err := fuzzer.loadCacheData()
	// if err != nil {
	// 	return nil, fmt.Errorf("error in loading cache data: %v", err)
	// }
	// contractInfoMap := cacheData.ContractInfoMap

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
		// fuzzer.logger.Warn("If using InvariantTesting, please set variableRecoverEnabled = true")
		attachInvariantTestCaseProvider(fuzzer)
	}

	// attach helper contract
	attachHelperContract(fuzzer)

	// fuzzer.dumpCacheData(cacheData)

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
			f.config.Fuzzing.StateGuidedConfig.EnabledStateConstruction,
			f.config.Fuzzing.StateGuidedConfig.EnabledStateDivision,
			f.config.Fuzzing.StateGuidedConfig.EnabledStateDirection,
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

	// deploy helperContract
	args := make([]any, 0)
	var addressList []common.Address
	for _, targetAddress := range fuzzer.config.Fuzzing.OnChainFuzzingConfig.TargetAddresses {
		addressList = append(addressList, common.HexToAddress(targetAddress))
	}
	args = append(args, addressList)
	msgData, err := FuzzHelperContract.CompiledContract().GetDeploymentMessageData(args)
	if err != nil {
		return fmt.Errorf("initial contract deployment failed for contract \"%v\", error: %v", FuzzHelperContract.Name(), err), nil
	}
	// msgData, _ := hex.DecodeString(FuzzHelperContractBytecode)
	// initBalance, _ := new(big.Int).SetString("50000000000000000000", 10) // 5 ** 19
	initBalance := new(big.Int).Div(fuzzer.config.Fuzzing.SenderAddressesBalances[0], big.NewInt(2))
	msg := calls.NewCallMessage(fuzzer.senders[0], nil, 0, initBalance, fuzzer.config.Fuzzing.BlockGasLimit, nil, nil, nil, msgData)
	msg.FillFromTestChainProperties(testChain)
	err = testChain.PendingBlockAddTx(msg.ToCoreMessage())
	if err != nil {
		return err, nil
	}

	err = testChain.PendingBlockCommit()
	if err != nil {
		return err, nil
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
			return fmt.Errorf("failed to attach execution trace to failed contract deployment tx: %v", err), nil
		}
		if cse.ExecutionTrace == nil {
			return fmt.Errorf("contract deployment tx returned a failed status: %v", block.MessageResults[0].ExecutionResult.Err), nil
		}

		// Return the execution error and the execution trace
		return fmt.Errorf("contract deployment tx returned a failed status: %v", block.MessageResults[0].ExecutionResult.Err), cse.ExecutionTrace
	}

	FuzzHelperContractAddr = block.MessageResults[0].Receipt.ContractAddress
	fuzzer.baseValueSet.AddAddress(FuzzHelperContractAddr)

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

func (f *Fuzzer) attachCallSequenceToCorpus(testChain *chain.TestChain, deployedContractBytecodes []*types.DeployedContractBytecode) error {

	// for token swap
	// for _, addr := range f.config.Fuzzing.OnChainFuzzingConfig.TargetAddresses {
	// 	var isExistPair bool
	// 	address := common.HexToAddress(addr)
	// 	isExistV2Pair, err := f.checkIsExistUniswapV2Pair(testChain, wethAddr, address)
	// 	if err != nil {
	// 		return fmt.Errorf("error in attachTokenSwapToCorpus: %v", err)
	// 	}
	// 	var callSequence calls.CallSequence
	// 	swapAmount, _ := new(big.Int).SetString("10000000000000000000", 10) // 10 ** 19
	// 	if isExistV2Pair {
	// 		tokenSwapElement := f.genUniswapV2SwapCallSequenceElement(testChain, swapAmount, address, f.senders[0], f.senders[0])
	// 		callSequence = append(callSequence, tokenSwapElement)
	// 		isExistPair = true
	// 	} else {
	// 		pairAddress, err := f.getUniswapV1Pair(testChain, address)
	// 		if err != nil {
	// 			return fmt.Errorf("error in attachTokenSwapToCorpus: %v", err)
	// 		}
	// 		if pairAddress != common.HexToAddress("0x") {
	// 			tokenSwapElement := f.genUniswapV1SwapCallSequenceElement(testChain, swapAmount, address, f.senders[0], pairAddress)
	// 			callSequence = append(callSequence, tokenSwapElement)
	// 			isExistPair = true
	// 		}
	// 	}

	// 	if isExistPair {
	// 		token := address
	// 		// deal with approve of sender
	// 		for _, contractBytecode := range deployedContractBytecodes {
	// 			matchedContract := f.contractDefinitions.MatchBytecode(contractBytecode.InitBytecode, contractBytecode.RuntimeBytecode)
	// 			if matchedContract != nil {
	// 				if _, ok := matchedContract.CompiledContract().Abi.Methods["approve"]; ok {
	// 					owner := f.senders[0]
	// 					spender := contractBytecode.Address
	// 					approveCallSequenceElement := f.genApproveCallSequenceElement(testChain, owner, spender, token, matchedContract)
	// 					approveCallSequenceElement.UnableSendWithHelperContract = true
	// 					callSequence = append(callSequence, approveCallSequenceElement)

	// 					// deal with approve of helperContract
	// 					approveMethod := FuzzHelperContract.CompiledContract().Abi.Methods["approve"]
	// 					msg := calls.NewCallMessageWithAbiValueData(owner, &FuzzHelperContractAddr, 0, big.NewInt(0), f.config.Fuzzing.TransactionGasLimit, nil, nil, nil, &calls.CallMessageDataAbiValues{
	// 						Method:      &approveMethod,
	// 						InputValues: []any{token, spender},
	// 					})
	// 					msg.FillFromTestChainProperties(testChain)
	// 					helperApproveCallSequenceElement := calls.NewCallSequenceElement(FuzzHelperContract, msg, 0, 0)
	// 					helperApproveCallSequenceElement.UnableSendWithHelperContract = true
	// 					callSequence = append(callSequence, helperApproveCallSequenceElement)
	// 				}
	// 			}
	// 		}

	// 		err = f.corpus.AddSequence(callSequence, big.NewInt(1), true)
	// 		if err != nil {
	// 			return fmt.Errorf("error in AddSequence in AddCallSequenceForSwap: %v", err)
	// 		}
	// 	}
	// }
	return nil
}

// run takes a base Chain in a setup state ready for testing, clones it, and begins executing fuzzed transaction calls
// and asserting properties are upheld. This runs until Fuzzer.ctx cancels the operation.
// Returns a boolean indicating whether Fuzzer.ctx has indicated we cancel the operation, and an error if one occurred.
func (fw *FuzzerWorker) runOnChain(baseTestChain *chain.TestChain) (bool, error) {
	// Clone our chain, attaching our necessary components for fuzzing post-genesis, prior to all blocks being copied.
	// This means any tracers added or events subscribed to within this inner function are done so prior to chain
	// setup (initial contract deployments), so data regarding that can be tracked as well.
	var err error

	cloneFunc := func(initializedChain *chain.TestChain) error {
		// Subscribe our chain event handlers
		initializedChain.Events.ContractDeploymentAddedEventEmitter.Subscribe(fw.onChainContractDeploymentAddedEvent)
		initializedChain.Events.ContractDeploymentRemovedEventEmitter.Subscribe(fw.onChainContractDeploymentRemovedEvent)

		// Emit an event indicating the worker has created its chain.
		err = fw.Events.FuzzerWorkerChainCreated.Publish(FuzzerWorkerChainCreatedEvent{
			Worker: fw,
			Chain:  initializedChain,
		})
		if err != nil {
			return fmt.Errorf("error returned by an event handler when emitting a worker chain created event: %v", err)
		}

		fw.initTestChain(initializedChain)
		return nil
	}

	fw.chain, err = baseTestChain.Clone(cloneFunc)

	// If we encountered an error during cloning, return it.
	if err != nil {
		return false, err
	}

	// Defer the closing of the test chain object
	defer fw.chain.Close()

	// Emit an event indicating the worker has setup its chain.
	err = fw.Events.FuzzerWorkerChainSetup.Publish(FuzzerWorkerChainSetupEvent{
		Worker: fw,
		Chain:  fw.chain,
	})
	if err != nil {
		return false, fmt.Errorf("error returned by an event handler when emitting a worker chain setup event: %v", err)
	}

	// Increase our generation metric as we successfully generated a test node
	fw.workerMetrics().workerStartupCount.Add(fw.workerMetrics().workerStartupCount, big.NewInt(1))

	// Save the current block number as all contracts have been deployed at this point, and we'll want to revert
	// to this state between testing.
	fw.testingBaseBlockNumber = fw.chain.HeadBlockNumber()

	// Enter the main fuzzing loop, restricting our memory database size based on our config variable.
	// When the limit is reached, we exit this method gracefully, which will cause the fuzzing to recreate
	// this worker with a fresh memory database.
	sequencesTested := 0
	for sequencesTested <= fw.fuzzer.config.Fuzzing.WorkerResetLimit {
		// If our context signalled to close the operation, exit our testing loop accordingly, otherwise continue.
		if utils.CheckContextDone(fw.fuzzer.ctx) {
			return true, nil
		}

		// Emit an event indicating the worker is about to test a new call sequence.
		err := fw.Events.CallSequenceTesting.Publish(FuzzerWorkerCallSequenceTestingEvent{
			Worker: fw,
		})
		if err != nil {
			return false, fmt.Errorf("error returned by an event handler when a worker emitted an event indicating testing of a new call sequence is starting: %v", err)
		}

		callSequence, shrinkVerifiers, err := fw.testNextCallSequence()
		if err != nil {
			return false, err
		}

		// If we have any requests to shrink call sequences, do so now.
		for _, shrinkVerifier := range shrinkVerifiers {
			_, err = fw.shrinkCallSequence(callSequence, shrinkVerifier)
			if err != nil {
				return false, err
			}
		}

		// Emit an event indicating the worker is about to test a new call sequence.
		err = fw.Events.CallSequenceTested.Publish(FuzzerWorkerCallSequenceTestedEvent{
			Worker: fw,
		})
		if err != nil {
			return false, fmt.Errorf("error returned by an event handler when a worker emitted an event indicating testing of a new call sequence has concluded: %v", err)
		}

		// Update our sequences tested metrics
		fw.workerMetrics().sequencesTested.Add(fw.workerMetrics().sequencesTested, big.NewInt(1))
		sequencesTested++
	}

	// We have not cancelled fuzzing operations, but this worker exited, signalling for it to be regenerated.
	return false, nil
}

// func pathExists(path string) (bool, error) {
// 	_, err := os.Stat(path)
// 	if err == nil {
// 		return true, nil
// 	}
// 	if os.IsNotExist(err) {
// 		return false, nil
// 	}
// 	return false, err
// }

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

	// for debug
	// testChain.AddTracer(executiontracer.NewExecutionTracer(fw.fuzzer.contractDefinitions, testChain.CheatCodeContracts()), true, false)

	if fw.fuzzer.config.Fuzzing.OnChainFuzzingConfig.IsOnChain {
		// copy accountState and attach accountState
		testChain.IsOnChain = true
		testChain.CacheAccountState = fw.fuzzer.fuzzerInitAccountState.initAccountState.DeepCopy()
		testChain.State().SetAccountState(testChain.CacheAccountState)
	}
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
