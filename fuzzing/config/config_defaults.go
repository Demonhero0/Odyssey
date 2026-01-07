package config

import (
	"math/big"

	testChainConfig "github.com/crytic/medusa/chain/config"
	"github.com/crytic/medusa/compilation"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/rs/zerolog"
)

// GetDefaultProjectConfig obtains a default configuration for a project. It populates a default compilation config
// based on the provided platform, or a nil one if an empty string is provided.
func GetDefaultProjectConfig(platform string) (*ProjectConfig, error) {
	var (
		compilationConfig *compilation.CompilationConfig
		chainConfig       *testChainConfig.TestChainConfig
		err               error
	)

	// Try to obtain a default compilation config for this platform.
	if platform != "" {
		compilationConfig, err = compilation.NewCompilationConfig(platform)
		if err != nil {
			return nil, err
		}
	}

	// Try to obtain a default chain config.
	chainConfig, err = testChainConfig.DefaultTestChainConfig()
	if err != nil {
		return nil, err
	}

	// Create a project configuration
	projectConfig := &ProjectConfig{
		Fuzzing: FuzzingConfig{
			Workers:                 10,
			WorkerResetLimit:        50,
			Timeout:                 0,
			TestLimit:               0,
			ShrinkLimit:             5_000,
			CallSequenceLength:      100,
			TargetContracts:         []string{},
			TargetContractsBalances: []*big.Int{},
			ConstructorArgs:         map[string]map[string]any{},
			CorpusDirectory:         "",
			CoverageEnabled:         false,
			StateGuidedConfig: StateGuidedConfig{
				EnabledStateGuided: false,
				// EnabledStateConstruction: false,
				EnabledStateDivision: false,
				EnabledCompression:   false,
			},
			MetricRecordConfig: MetricRecordConfig{
				CoverageEnabled: true,
				StateEnabled:    false,
				SlotEnabled:     false,
			},
			SenderAddresses: []string{
				"0x10000",
				"0x20000",
				"0x30000",
			},
			SenderAddressesBalances: []*big.Int{
				new(big.Int).Div(abi.MaxInt256, big.NewInt(2)),
				new(big.Int).Div(abi.MaxInt256, big.NewInt(2)),
				new(big.Int).Div(abi.MaxInt256, big.NewInt(2)),
			},
			DeployerAddress:        "0x30000",
			MaxBlockNumberDelay:    60480,
			MaxBlockTimestampDelay: 604800,
			BlockGasLimit:          125_000_000,
			TransactionGasLimit:    12_500_000,
			Testing: TestingConfig{
				StopOnFailedTest:             true,
				StopOnFailedContractMatching: false,
				StopOnNoTests:                true,
				TestAllContracts:             false,
				TraceAll:                     false,
				AssertionTesting: AssertionTestingConfig{
					Enabled:         true,
					TestViewMethods: false,
					PanicCodeConfig: PanicCodeConfig{
						FailOnAssertion: true,
					},
				},
				PropertyTesting: PropertyTestingConfig{
					Enabled: true,
					TestPrefixes: []string{
						"property_",
					},
				},
				OptimizationTesting: OptimizationTestingConfig{
					Enabled: true,
					TestPrefixes: []string{
						"optimize_",
					},
				},
				ContractCallConfig: ContractCallConfig{
					EnabledContractCall:     false,
					ContractCallProbability: 0.5,
					EnabledInternalCall:     false,
					InternalCallProbability: 0.5,
				},
				InvariantChecking: InvariantCheckingConfig{
					Enabled: false,
				},
			},
			TestChainConfig: *chainConfig,

			// variable recover
			VariableRecoverConfig: VariableRecoverConfig{
				TraceStorage: false,
			},
			OnChainFuzzingConfig: OnChainFuzzingConfig{
				IsOnChain: false,
			},
		},
		Compilation: compilationConfig,
		Logging: LoggingConfig{
			Level:        zerolog.InfoLevel,
			LogDirectory: "",
			NoColor:      false,
		},
	}

	// Return the project configuration
	return projectConfig, nil
}
