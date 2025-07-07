package cmd

import (
	"fmt"
	"math/big"
	"time"

	"github.com/crytic/medusa/fuzzing/invariant"
	"github.com/crytic/medusa/utils/rpc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	vm "github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/spf13/cobra"
)

// fuzzOnChainCmd represents the command provider for fuzzing
var replayCmd = &cobra.Command{
	Use:           "replay",
	Short:         "Replay a transaction",
	Long:          `Replay a transaction`,
	RunE:          cmdRunReplay,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	// Add all the flags allowed for the fuzz command
	err := addReplayFlags()
	if err != nil {
		cmdLogger.Panic("Failed to initialize the fuzz command", err)
	}

	// Add the fuzz command and its associated flags to the root command
	rootCmd.AddCommand(replayCmd)
}

func addReplayFlags() error {
	// Prevent alphabetical sorting of usage message
	replayCmd.Flags().SortFlags = false
	// Config file
	replayCmd.Flags().String("tx", "", "transaction hash")

	replayCmd.Flags().String("node-url", "", "url of on-chain node")

	return nil
}

// record-replay: func replayAction for replay command
func cmdRunReplay(cmd *cobra.Command, args []string) error {
	var err error
	var txhash string
	RPCURL := "http://localhost:8545"

	// If --target-addresses was used
	if cmd.Flags().Changed("tx") {
		txhash, err = cmd.Flags().GetString("tx")
		if err != nil {
			return err
		}
	}
	// Update on-chain node
	if cmd.Flags().Changed("node-url") {
		RPCURL, err = cmd.Flags().GetString("node-url")
		if err != nil {
			return err
		}
	}

	provider := rpc.NodeProvider{
		NodeURL: RPCURL,
	}

	txReceipt, err := provider.GetTransactionReceipt(common.HexToHash(txhash))
	fmt.Println(txReceipt, err)
	blockNumber := txReceipt.BlockNumber
	position := txReceipt.TransactionIndex
	block, err := provider.GetBlockByNumber(blockNumber)

	accountState := state.NewAccountState(true, &provider, blockNumber.Int64()-1)

	msg, blockCtx, txCtx, statedb, chainConfig, err := stateAtTransaction(blockNumber, position, block, accountState, &provider)

	if err != nil {
		return err
	}
	fmt.Println("tracing", txhash)
	// init tracer
	tracer := invariant.NewTxTracer()
	tracer.SetRecodingState([]common.Address{})
	vmConfig := vm.Config{
		Tracer: tracer,
	}
	evm := vm.NewEVM(blockCtx, txCtx, statedb, chainConfig, vmConfig)

	statedb.SetTxContext(common.HexToHash(txhash), int(position))
	_, err = core.ApplyMessageOnChain(evm, msg, new(core.GasPool).AddGas(msg.GasLimit))

	trace := tracer.GetTrace()
	fmt.Print(trace.Log().ColorString())
	return err
}

func stateAtTransaction(blockNumber *big.Int, position uint, block *types.Block, accountState *state.AccountState, provider *rpc.NodeProvider) (*core.Message, vm.BlockContext, vm.TxContext, *state.StateDB, *params.ChainConfig, error) {
	//Set up Executing Environment
	var (
		chainConfig *params.ChainConfig
		statedb     *state.StateDB
		// blobBaseFee *big.Int
		random *common.Hash
	)

	// if block.Header().ExcessBlobGas != nil {
	// 	blobBaseFee = eip4844.CalcBlobFee(*block.Header().ExcessBlobGas)
	// }
	if block.Header().Difficulty.Sign() == 0 {
		random = &block.Header().MixDigest
	}

	// chainConfig
	chainConfig = &params.ChainConfig{}
	*chainConfig = *params.MainnetChainConfig
	// disable DAOForkSupport, otherwise account states will be overwritten
	chainConfig.DAOForkSupport = false

	signer := types.MakeSigner(chainConfig, block.Number(), block.Time())
	statedb = newStateDB(block, chainConfig)
	statedb.SetAccountState(accountState)
	for idx, tx := range block.Transactions() {
		msg, _ := core.TransactionToMessage(tx, signer, block.BaseFee())
		txCtx := core.NewEVMTxContext(msg)
		blockCtx := vm.BlockContext{
			CanTransfer: core.CanTransfer,
			Transfer:    core.Transfer,
			Coinbase:    block.Coinbase(),
			BlockNumber: blockNumber,
			Time:        block.Time(),
			Difficulty:  block.Difficulty(),
			GasLimit:    block.GasLimit(),
			BaseFee:     block.BaseFee(),
			// BlobBaseFee: blobBaseFee,
			GetHash: getHashRPCFn(block, accountState, provider),
			Random:  random,
		}

		statedb.SetTxContext(tx.Hash(), idx)
		if idx == int(position) {
			return msg, blockCtx, txCtx, statedb, chainConfig, nil
		}
		fmt.Println("preparing", blockNumber, idx)
		vmenv := vm.NewEVM(blockCtx, txCtx, statedb, chainConfig, vm.Config{})

		if _, err := core.ApplyMessageOnChain(vmenv, msg, new(core.GasPool).AddGas(tx.Gas())); err != nil {
			return nil, blockCtx, txCtx, statedb, chainConfig, fmt.Errorf("transaction %#x failed: %v", tx.Hash(), err)
		}
		// Ensure any modifications are committed to the state
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		statedb.Finalise(vmenv.ChainConfig().IsEIP158(block.Number()))

		// limit time
		time.Sleep(500 * time.Millisecond)
	}
	return nil, vm.BlockContext{}, vm.TxContext{}, statedb, chainConfig, fmt.Errorf("transaction index %d out of range for block %#x", position, block.Hash())
}

func newStateDB(block *types.Block, chainConfig *params.ChainConfig) *state.StateDB {
	db := rawdb.NewMemoryDatabase()
	statedb, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		fmt.Println(err)
	}

	_, err = statedb.Commit(chainConfig.IsEIP158(block.Number()))
	if err != nil {
		panic(fmt.Errorf("error calling statedb.Commit() in MakeOffTheChainStateDB(): %v", err))
	}
	return statedb
}

func getHashRPCFn(block *types.Block, accountState *state.AccountState, provider *rpc.NodeProvider) func(num uint64) common.Hash {

	return func(num uint64) common.Hash {
		var h common.Hash
		if num == block.NumberU64() {
			h = block.Hash()
		} else {
			header, _ := provider.GetHeaderByNumber(big.NewInt(int64(num)))
			h = header.Hash()
		}
		return h
	}
}
