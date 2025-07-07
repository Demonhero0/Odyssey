package invariant

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/crytic/medusa/chain/types"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

const TokenTraceResultKey = "TokenTraceResultKey"

func getABIString() string {
	return `[
    {
        "type": "function",
        "name": "swapExactTokensForETHUtil",
        "inputs": [
            {
                "name": "token",
                "type": "address",
                "internalType": "address"
            },
            {
                "name": "amountIn",
                "type": "uint256",
                "internalType": "uint256"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "uint256",
                "internalType": "uint256"
            }
        ],
        "stateMutability": "view"
    },
    {
        "constant": false,
        "inputs": [
            {
                "name": "dst",
                "type": "address"
            },
            {
                "name": "wad",
                "type": "uint256"
            }
        ],
        "name": "transfer",
        "outputs": [
            {
                "name": "",
                "type": "bool"
            }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {
                "name": "src",
                "type": "address"
            },
            {
                "name": "dst",
                "type": "address"
            },
            {
                "name": "wad",
                "type": "uint256"
            }
        ],
        "name": "transferFrom",
        "outputs": [
            {
                "name": "",
                "type": "bool"
            }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    }
	]`
}

type TokenTracer struct {
	tokens map[common.Address]bool
	Abi    abi.ABI

	worker         FuzzerWorker
	topInput       []byte
	originalFrom   common.Address
	originalTo     common.Address
	methodSig      string
	stateVariables map[string]*StateValue

	isEmitTransferEvent bool
}

type TokenStateVariables struct {
	MethodSig      string
	StateVariables map[string]*StateValue
}

type FuzzerWorker interface {
	GetTokenBalance(addr, token common.Address) (*big.Int, error)
}

func NewTokenTracer(fw FuzzerWorker, tokenList []string) *TokenTracer {
	erc20Abi, err := abi.JSON(strings.NewReader(getABIString()))
	if err != nil {
		fmt.Println("Parser error", err)
	}

	tokenTracer := &TokenTracer{
		tokens: make(map[common.Address]bool),
		Abi:    erc20Abi,
		worker: fw,
	}

	for _, token := range tokenList {
		tokenTracer.tokens[common.HexToAddress(token)] = true
	}

	return tokenTracer
}

func (t *TokenTracer) Tokens() map[common.Address]bool {
	return t.tokens
}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *TokenTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {

	// record some pre state
	if t.worker != nil {
		t.topInput = input
		t.originalFrom = from
		t.originalTo = to
		t.stateVariables = make(map[string]*StateValue)
		t.methodSig = t.handleInputToGetState(input, "pre")
		t.isEmitTransferEvent = false
	}
}

func (t *TokenTracer) handleInputToGetState(input []byte, stage string) string {
	method, err := t.Abi.MethodById(input)
	if err == nil {
		switch method.Sig {
		case "transfer(address,uint256)":
			inputValues, err := method.Inputs.Unpack(input[4:])
			if err == nil {
				if stage == "pre" {
					t.stateVariables["amount"] = &StateValue{
						Value: inputValues[1].(*big.Int),
						Type:  "uint256",
					}
				}

				fromBalance, _ := t.worker.GetTokenBalance(t.originalFrom, t.originalTo)
				toBalance, err := t.worker.GetTokenBalance(inputValues[0].(common.Address), t.originalTo)
				if err != nil {
					fmt.Println(err)
				}

				t.stateVariables[fmt.Sprintf("%s(%s)", stage, "balanceOf[from]")] = &StateValue{
					Value: fromBalance,
					Type:  "uint256",
				}
				t.stateVariables[fmt.Sprintf("%s(%s)", stage, "balanceOf[to]")] = &StateValue{
					Value: toBalance,
					Type:  "uint256",
				}
				t.stateVariables["from"] = &StateValue{
					Value: t.originalFrom,
					Type:  "address",
				}
				t.stateVariables["to"] = &StateValue{
					Value: inputValues[0].(common.Address),
					Type:  "address",
				}
				// fmt.Println(method.Sig, t.originalFrom, fromBalance, inputValues[0].(common.Address), toBalance, inputValues[1].(*big.Int))
			}
			return method.Sig
		case "transferFrom(address,address,uint256)":
			inputValues, err := method.Inputs.Unpack(input[4:])
			if err == nil {
				if stage == "pre" {
					t.stateVariables["amount"] = &StateValue{
						Value: inputValues[2].(*big.Int),
						Type:  "uint256",
					}
				}

				fromBalance, _ := t.worker.GetTokenBalance(inputValues[0].(common.Address), t.originalTo)
				toBalance, err := t.worker.GetTokenBalance(inputValues[1].(common.Address), t.originalTo)
				if err != nil {
					fmt.Println(err)
				}

				t.stateVariables[fmt.Sprintf("%s(%s)", stage, "balanceOf[from]")] = &StateValue{
					Value: fromBalance,
					Type:  "uint256",
				}
				t.stateVariables[fmt.Sprintf("%s(%s)", stage, "balanceOf[to]")] = &StateValue{
					Value: toBalance,
					Type:  "uint256",
				}
				t.stateVariables["from"] = &StateValue{
					Value: inputValues[0].(common.Address),
					Type:  "address",
				}
				t.stateVariables["to"] = &StateValue{
					Value: inputValues[1].(common.Address),
					Type:  "address",
				}
			}
			return method.Sig
		default:
			return ""
		}
	}
	return ""
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *TokenTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	// record some post state
	if err == nil && t.isEmitTransferEvent {
		t.handleInputToGetState(t.topInput, "post")
	}
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *TokenTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	// skip if the previous op caused an error
	if err != nil {
		return
	}

	// recording log
	switch op {
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

		// data, err := getMemoryCopyPadded(scope.Memory, int64(mStart.Uint64()), int64(mSize.Uint64()))
		// if err != nil {
		// 	// mSize was unrealistically large
		// 	log.Warn("failed to copy CREATE2 input", "err", err, "tracer", "callTracer", "offset", mStart, "size", mSize)
		// 	return
		// }

		if len(topics) > 0 && topics[0].String() == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" && len(topics) == 3 {
			// fmt.Println("find token", scope.Contract.Address())
			t.tokens[scope.Contract.Address()] = true

			if scope.Contract.Address() == t.originalTo {
				t.isEmitTransferEvent = true
			}
		}
	}
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *TokenTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
}

// captureEnteredCallFrame is a helper method used when a new call frame is entered to record information about it.
func (t *TokenTracer) captureEnteredCallFrame(from common.Address, to common.Address, input []byte, isContractCreation bool, value *big.Int, typ vm.OpCode, gas uint64, isStart bool) {
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *TokenTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
}

// CaptureFault implements the EVMLogger interface to trace an execution fault.
func (t *TokenTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}

func (t *TokenTracer) CaptureTxStart(gasLimit uint64) {
}

func (t *TokenTracer) CaptureTxEnd(restGas uint64) {
}

func (t *TokenTracer) captureExitedCallFrame(output []byte, err error) {
}

func (t *TokenTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	if t.methodSig != "" {
		results.AdditionalResults[TokenTraceResultKey] = TokenStateVariables{
			MethodSig:      t.methodSig,
			StateVariables: t.stateVariables,
		}
	}
}
