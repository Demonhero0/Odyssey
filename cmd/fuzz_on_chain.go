package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/crytic/medusa/cmd/exitcodes"
	"github.com/crytic/medusa/logging/colors"

	"github.com/crytic/medusa/fuzzing"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/spf13/cobra"
)

// fuzzOnChainCmd represents the command provider for fuzzing
var fuzzOnChainCmd = &cobra.Command{
	Use:               "fuzz-on-chain",
	Short:             "Starts a fuzzing campaign",
	Long:              `Starts a fuzzing campaign`,
	Args:              cmdValidateFuzzArgs,
	ValidArgsFunction: cmdValidFuzzArgs,
	RunE:              cmdRunFuzzOnChain,
	SilenceUsage:      true,
	SilenceErrors:     true,
}

func init() {
	// Add all the flags allowed for the fuzz command
	err := addFuzzOnChainFlags()
	if err != nil {
		cmdLogger.Panic("Failed to initialize the fuzz command", err)
	}

	// Add the fuzz command and its associated flags to the root command
	rootCmd.AddCommand(fuzzOnChainCmd)
}

func addFuzzOnChainFlags() error {
	// Get the default project config and throw an error if we cant
	defaultConfig, err := config.GetDefaultProjectConfig(DefaultCompilationPlatform)
	if err != nil {
		return err
	}
	// Prevent alphabetical sorting of usage message
	fuzzOnChainCmd.Flags().SortFlags = false
	// Config file
	fuzzOnChainCmd.Flags().String("config", "", "path to config file")

	// Target contracts
	fuzzOnChainCmd.Flags().StringSlice("target-addresses", []string{},
		fmt.Sprintf("target addresses for fuzz testing"))
	// fuzzOnChainCmd.Flags().String("target-addresses", "", "address of target contract")

	fuzzOnChainCmd.Flags().Int("blocknumber", 0, "block height for testing")

	fuzzOnChainCmd.Flags().String("node-url", "", "url of on-chain node")

	fuzzOnChainCmd.Flags().String("etherscan-api-key", "", "api key of etherscan")

	// Logging color
	fuzzOnChainCmd.Flags().Bool("invariant-guided", false, "turn on invariant-guided mode")

	// Number of workers
	fuzzOnChainCmd.Flags().Int("workers", 0,
		fmt.Sprintf("number of fuzzer workers (unless a config file is provided, default is %d)", defaultConfig.Fuzzing.Workers))

	// Trace all
	fuzzOnChainCmd.Flags().Bool("trace-all", false,
		fmt.Sprintf("print the execution trace for every element in a shrunken call sequence instead of only the last element (unless a config file is provided, default is %t)", defaultConfig.Fuzzing.Testing.TraceAll))

	// Corpus directory
	fuzzOnChainCmd.Flags().String("corpus-dir", "",
		fmt.Sprintf("directory path for corpus items and coverage reports (unless a config file is provided, default is %q)", defaultConfig.Fuzzing.CorpusDirectory))

	// coverage guide
	fuzzOnChainCmd.Flags().Bool("coverage-guide", false, "enable coverage-guide")

	// state guide
	fuzzOnChainCmd.Flags().Bool("state-guide", false, "enable state guide")

	// state construction
	fuzzOnChainCmd.Flags().Bool("state-construction", false, "enable state construction")

	// state division
	fuzzOnChainCmd.Flags().Bool("state-division", false, "enable state division")

	// result output path
	fuzzOnChainCmd.Flags().String("output", "", "path to output file")
	return nil
}

// updateProjectConfigWithFuzzFlags will update the given projectConfig with any CLI arguments that were provided to the fuzz command
func updateProjectConfigWithFuzzOnChainFlags(cmd *cobra.Command, projectConfig *config.ProjectConfig) error {
	var err error

	// If --target-addresses was used
	if cmd.Flags().Changed("target-addresses") {
		projectConfig.Fuzzing.OnChainFuzzingConfig.TargetAddresses, err = cmd.Flags().GetStringSlice("target-addresses")
		if err != nil {
			return err
		}
	}

	// Update number of workers
	if cmd.Flags().Changed("blocknumber") {
		projectConfig.Fuzzing.OnChainFuzzingConfig.BlockNumber, err = cmd.Flags().GetInt("blocknumber")
		if err != nil {
			return err
		}
	}

	// Update on-chain node
	if cmd.Flags().Changed("node-url") {
		projectConfig.Fuzzing.OnChainFuzzingConfig.NodeUrl, err = cmd.Flags().GetString("node-url")
		if err != nil {
			return err
		}
	}

	// Update timeout
	if cmd.Flags().Changed("etherscan-api-key") {
		projectConfig.Fuzzing.OnChainFuzzingConfig.EtherscanApiKey, err = cmd.Flags().GetString("etherscan-api-key")
		if err != nil {
			return err
		}
	}

	// Update number of workers
	if cmd.Flags().Changed("workers") {
		projectConfig.Fuzzing.Workers, err = cmd.Flags().GetInt("workers")
		if err != nil {
			return err
		}
	}

	// Update trace all enablement
	if cmd.Flags().Changed("trace-all") {
		projectConfig.Fuzzing.Testing.TraceAll, err = cmd.Flags().GetBool("trace-all")
		if err != nil {
			return err
		}
	}

	// Update corpus directory
	if cmd.Flags().Changed("corpus-dir") {
		projectConfig.Fuzzing.CorpusDirectory, err = cmd.Flags().GetString("corpus-dir")
		if err != nil {
			return err
		}
	}

	// Update logging color mode
	if cmd.Flags().Changed("invariant-guided") {
		projectConfig.Fuzzing.Testing.InvariantChecking.InvariantGuided, err = cmd.Flags().GetBool("invariant-guided")
		if err != nil {
			return err
		}
	}

	// Update state guide
	if cmd.Flags().Changed("state-guide") {
		projectConfig.Fuzzing.StateGuidedConfig.EnabledStateGuided, err = cmd.Flags().GetBool("state-guide")
		if err != nil {
			return err
		}
	}

	// Update state construction
	if cmd.Flags().Changed("state-construction") {
		projectConfig.Fuzzing.StateGuidedConfig.EnabledStateConstruction, err = cmd.Flags().GetBool("state-construction")
		if err != nil {
			return err
		}
	}

	// Update state division
	if cmd.Flags().Changed("state-division") {
		projectConfig.Fuzzing.StateGuidedConfig.EnabledStateDivision, err = cmd.Flags().GetBool("state-division")
		if err != nil {
			return err
		}
	}

	// Update state guide
	if cmd.Flags().Changed("coverage-guide") {
		projectConfig.Fuzzing.CoverageEnabled, err = cmd.Flags().GetBool("coverage-guide")
		if err != nil {
			return err
		}
	}

	projectConfig.Fuzzing.OnChainFuzzingConfig.IsOnChain = true
	return nil
}

// cmdRunFuzz executes the CLI fuzz command and navigates through the following possibilities:
// #1: We will search for either a custom config file (via --config) or the default (medusa.json).
// If we find it, read it. If we can't read it, throw an error.
// #2: If a custom file was provided (--config was used), and we can't find the file, throw an error.
// #3: If medusa.json can't be found, use the default project configuration.
func cmdRunFuzzOnChain(cmd *cobra.Command, args []string) error {
	var projectConfig *config.ProjectConfig

	// Check to see if --config flag was used and store the value of --config flag
	configFlagUsed := cmd.Flags().Changed("config")
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		cmdLogger.Error("Failed to run the fuzz command", err)
		return err
	}

	// If --config was not used, look for `medusa.json` in the current work directory
	if !configFlagUsed {
		workingDirectory, err := os.Getwd()
		if err != nil {
			cmdLogger.Error("Failed to run the fuzz command", err)
			return err
		}
		configPath = filepath.Join(workingDirectory, DefaultProjectConfigFilename)
	}

	// Check to see if the file exists at configPath
	_, existenceError := os.Stat(configPath)

	// Possibility #1: File was found
	if existenceError == nil {
		// Try to read the configuration file and throw an error if something goes wrong
		cmdLogger.Info("Reading the configuration file at: ", colors.Bold, configPath, colors.Reset)
		projectConfig, err = config.ReadProjectConfigFromFile(configPath)
		if err != nil {
			cmdLogger.Error("Failed to run the fuzz command", err)
			return err
		}
	}

	// Possibility #2: If the --config flag was used, and we couldn't find the file, we'll throw an error
	if configFlagUsed && existenceError != nil {
		cmdLogger.Error("Failed to run the fuzz command", err)
		return existenceError
	}

	// Possibility #3: --config flag was not used and medusa.json was not found, so use the default project config
	if !configFlagUsed && existenceError != nil {
		cmdLogger.Warn(fmt.Sprintf("Unable to find the config file at %v, will use the default project configuration for the "+
			"%v compilation platform instead", configPath, DefaultCompilationPlatform))

		projectConfig, err = config.GetDefaultProjectConfig(DefaultCompilationPlatform)
		if err != nil {
			cmdLogger.Error("Failed to run the fuzz command", err)
			return err
		}
	}

	// Update the project configuration given whatever flags were set using the CLI
	err = updateProjectConfigWithFuzzOnChainFlags(cmd, projectConfig)
	if err != nil {
		cmdLogger.Error("Failed to run the fuzz command", err)
		return err
	}

	// Change our working directory to the parent directory of the project configuration file
	// This is important as when we compile for a given platform, the paths may be relative to wherever the
	// configuration is supplied from. Providing a file path explicitly is optional anyways, so we _should_
	// be in the config directory when running this.
	err = os.Chdir(filepath.Dir(configPath))
	if err != nil {
		cmdLogger.Error("Failed to run the fuzz command", err)
		return err
	}

	// Create our fuzzing
	fuzzer, fuzzErr := fuzzing.NewFuzzerOnCahin(*projectConfig)
	if fuzzErr != nil {
		cmdLogger.Error("Failed to NewFuzzerOnChain", fuzzErr)
		return exitcodes.NewErrorWithExitCode(fuzzErr, exitcodes.ExitCodeHandledError)
	}

	// Stop our fuzzing on keyboard interrupts
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		fuzzer.Stop()
	}()

	// Start the fuzzing process with our cancellable context.
	fuzzErr = fuzzer.StartOnChain()
	if fuzzErr != nil {
		return exitcodes.NewErrorWithExitCode(fuzzErr, exitcodes.ExitCodeHandledError)
	}

	// If we have no error and failed test cases, we'll want to return a special exit code
	if fuzzErr == nil && len(fuzzer.TestCasesWithStatus(fuzzing.TestCaseStatusFailed)) > 0 {
		return exitcodes.NewErrorWithExitCode(fuzzErr, exitcodes.ExitCodeTestFailed)
	}

	outputFlagUsed := cmd.Flags().Changed("output")
	if outputFlagUsed {
		outputPath, err := cmd.Flags().GetString("output")
		if err != nil {
			cmdLogger.Error("Failed to run the fuzz command", err)
			return err
		}
		// dump state and coverage
		resConfigPath := outputPath
		file, err := os.Create(resConfigPath)
		if err != nil {
			fmt.Println("Error:", err)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		err = encoder.Encode(fuzzer.StateAndCoverage)
		if err != nil {
			fmt.Println("Error:", err)
		}
	}

	return fuzzErr
}
