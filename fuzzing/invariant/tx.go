package invariant

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Log struct {
	Address  common.Address `json:"address"`
	Topics   []common.Hash  `json:"topics"`
	Data     []byte         `json:"data"`
	Position uint           `json:"index"`
}

type Transaction struct {
	TxHash      string     `json:"txHash"`
	BlockNumber *big.Int   `json:"blockNumber"`
	Timestamp   uint64     `json:"timestamp"`
	TxIndex     int        `json:"position"`
	InitialGas  uint64     `json:"-"`
	Call        *CallFrame `json:"call"`
}

type State = map[common.Address]*Account
type Account struct {
	Balance *big.Int                    `json:"balance,omitempty"`
	Code    []byte                      `json:"code,omitempty"`
	Nonce   uint64                      `json:"nonce,omitempty"`
	Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
}

func (a *Account) Exists() bool {
	return a.Nonce > 0 || len(a.Code) > 0 || len(a.Storage) > 0 || (a.Balance != nil && a.Balance.Sign() != 0)
}

type CallFrame struct {
	Type         string         `json:"type"`
	From         common.Address `json:"from"`
	To           common.Address `json:"to"`
	Value        *big.Int       `json:"value"`
	Input        []byte         `json:"input"`
	Output       []byte         `json:"output"`
	IsContract   bool           `json:"isContract"`
	CodeAddress  common.Address `json:"codeAddress"`
	Gas          uint64         `json:"gas"`
	GasUsed      uint64         `json:"gasUsed"`
	Error        error          `json:"err"`
	RevertReason string         `json:"revertReason,omitempty"`
	Logs         []*Log         `json:"logs"`
	Calls        []*CallFrame   `json:"calls"`

	// recording state
	IsState   bool                    `json:"isState"`
	Create    bool                    `json:"-"`
	Created   map[common.Address]bool `json:"-"`
	Deleted   map[common.Address]bool `json:"-"`
	PreState  State                   `json:"preState,omitempty"`
	PostState State                   `json:"postState,omitempty"`

	// medusa
	SelfDestructed bool `json:"selfDestructed"`
	// for parsing input
	ConstructorArgsData []byte            `json:"-"`
	ToContractName      string            `json:"-"`
	ToContractAbi       *abi.ABI          `json:"-"`
	CodeContractName    string            `json:"-"`
	CodeContractAbi     *abi.ABI          `json:"-"`
	CodeRuntimeBytecode []byte            `json:"-"`
	ToInitBytecode      []byte            `json:"-"`
	ToRuntimeBytecode   []byte            `json:"-"`
	StorageExtractor    *StorageExtractor `json:"-"`
}

func (callFrame *CallFrame) GetStorage(addr common.Address, stage string) (map[common.Hash]common.Hash, bool) {
	var returnStorage map[common.Hash]common.Hash
	var existStorage bool
	if stage == "pre" {
		state, existState := callFrame.PreState[addr]
		if existState {
			returnStorage = state.Storage
			existStorage = true
		}
	} else if stage == "post" {
		state, existState := callFrame.PostState[addr]
		if existState {
			returnStorage = state.Storage
			existStorage = true
		}
	} else {
		existStorage = false
	}
	return returnStorage, existStorage
}

func (callFrame *CallFrame) GetTo() common.Address          { return callFrame.To }
func (callFrame *CallFrame) GetFrom() common.Address        { return callFrame.From }
func (callFrame *CallFrame) GetInput() []byte               { return callFrame.Input }
func (callFrame *CallFrame) GetConstructorArgsData() []byte { return callFrame.ConstructorArgsData }
func (callFrame *CallFrame) GetCodeContractAbi() *abi.ABI   { return callFrame.CodeContractAbi }
func (callFrame *CallFrame) GetStorageExtractor() *StorageExtractor {
	return callFrame.StorageExtractor
}
func (c *CallFrame) IsContractCreation() bool {
	return c.Type == "CREATE" || c.Type == "CREATE2"
}
func (c *CallFrame) IsProxyCall() bool {
	return c.To != c.CodeAddress
}

func (c *CallFrame) DumpTree(path string) {
	b, _ := json.Marshal(*c)
	os.WriteFile(path, b, 0644)
}

func (transaction *Transaction) DumpTransaction(dumpPath string) {
	b, _ := json.Marshal(*transaction)
	os.WriteFile(dumpPath+"/"+transaction.BlockNumber.String()+"_"+strconv.Itoa(transaction.TxIndex)+".json", b, 0644)
}

func (transaction *Transaction) DumpTreeWithTxHash(dumpPath string) {
	b, _ := json.Marshal(*transaction)
	// fmt.Println("DumpTreeWithTxHash", transaction.TxHash)
	os.WriteFile(dumpPath+"/"+transaction.TxHash+".json", b, 0644)
}

func LoadTx(path string) Transaction {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("LoadTx error:", err)
	}
	ExTx := Transaction{}
	err = json.Unmarshal([]byte(file), &ExTx)
	if err != nil {
		fmt.Println("Json to struct error:", err)
	}
	return ExTx
}

func (transaction *Transaction) ParseTransaction() {
	fmt.Println(transaction.BlockNumber, transaction.Timestamp, transaction.TxIndex)
	callFrame := transaction.Call
	for _, tx := range callFrame.Calls {
		ParseCallFrameTree(tx, 0)
	}

	for _, event := range callFrame.Logs {
		parseEvent(event, 0)
	}
}

func ParseCallFrameTree(callFrame *CallFrame, depth int) {
	fmt.Println(strings.Repeat("-", depth+1), depth, callFrame.Type, fmt.Sprintf("sender(%s)", callFrame.From), fmt.Sprintf("to(%s)", callFrame.To))
	for _, tx := range callFrame.Calls {
		ParseCallFrameTree(tx, depth+1)
	}

	for _, event := range callFrame.Logs {
		parseEvent(event, depth)
	}
}

func parseEvent(event *Log, depth int) {
	fmt.Println(strings.Repeat("-", depth+2), depth+1, "event", event.Topics)
}

// MarshalJSON marshals as JSON.
func (c CallFrame) MarshalJSON() ([]byte, error) {
	type callFrame0 struct {
		Type         string         `json:"-"`
		From         common.Address `json:"from"`
		Gas          hexutil.Uint64 `json:"gas"`
		GasUsed      hexutil.Uint64 `json:"gasUsed"`
		To           common.Address `json:"to,omitempty" rlp:"optional"`
		Input        string         `json:"input" rlp:"optional"`
		Output       string         `json:"output,omitempty" rlp:"optional"`
		Error        string         `json:"error,omitempty" rlp:"optional"`
		RevertReason string         `json:"revertReason,omitempty"`
		Calls        []*CallFrame   `json:"calls,omitempty" rlp:"optional"`
		Logs         []*Log         `json:"logs,omitempty" rlp:"optional"`
		Value        *hexutil.Big   `json:"value,omitempty" rlp:"optional"`
		TypeString   string         `json:"type"`

		// recoding state
		IsState   bool  `json:"isState"`
		PreState  State `json:"preState,omitempty"`
		PostState State `json:"postState,omitempty"`
	}
	var enc callFrame0
	enc.Type = c.Type
	enc.From = c.From
	enc.Gas = hexutil.Uint64(c.Gas)
	enc.GasUsed = hexutil.Uint64(c.GasUsed)
	enc.To = c.To
	enc.Input = "0x" + hex.EncodeToString(c.Input)
	enc.Output = "0x" + hex.EncodeToString(c.Output)
	if c.Error != nil {
		enc.Error = c.Error.Error()
	} else {
		enc.Error = ""
	}
	enc.RevertReason = c.RevertReason
	enc.Calls = c.Calls
	enc.Logs = c.Logs
	enc.Value = (*hexutil.Big)(c.Value)
	enc.TypeString = c.Type

	enc.IsState = c.IsState
	enc.PreState = c.PreState
	enc.PostState = c.PostState
	return json.Marshal(&enc)
}

func (l Log) MarshalJSON() ([]byte, error) {
	type log0 struct {
		Address  common.Address `json:"address"`
		Topics   []common.Hash  `json:"topics"`
		Data     string         `json:"data"`
		Position uint           `json:"index"`
	}
	var log log0
	log.Address = l.Address
	log.Topics = l.Topics
	log.Data = "0x" + hex.EncodeToString(l.Data)
	log.Position = l.Position
	return json.Marshal(&log)
}

func (account Account) MarshalJSON() ([]byte, error) {
	type account0 struct {
		Balance *big.Int                    `json:"balance,omitempty"`
		Code    string                      `json:"code,omitempty"`
		Nonce   uint64                      `json:"nonce,omitempty"`
		Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
	}

	var s account0
	s.Balance = (*big.Int)(account.Balance)
	// s.Code = hex.EncodeToString(account.Code)
	s.Nonce = account.Nonce
	s.Storage = account.Storage
	return json.Marshal(&s)
}

// UnmarshalJSON unmarshals from JSON.
// func (c *callFrame) UnmarshalJSON(input []byte) error {
// 	type callFrame0 struct {
// 		Type         *string         `json:"-"`
// 		From         *common.Address `json:"from"`
// 		Gas          *hexutil.Uint64 `json:"gas"`
// 		GasUsed      *hexutil.Uint64 `json:"gasUsed"`
// 		To           *common.Address `json:"to,omitempty" rlp:"optional"`
// 		Input        *hexutil.Bytes  `json:"input" rlp:"optional"`
// 		Output       *hexutil.Bytes  `json:"output,omitempty" rlp:"optional"`
// 		Error        *string         `json:"error,omitempty" rlp:"optional"`
// 		RevertReason *string         `json:"revertReason,omitempty"`
// 		Calls        []callFrame     `json:"calls,omitempty" rlp:"optional"`
// 		Logs         []callLog       `json:"logs,omitempty" rlp:"optional"`
// 		Value        *hexutil.Big    `json:"value,omitempty" rlp:"optional"`
// 	}
// 	var dec callFrame0
// 	if err := json.Unmarshal(input, &dec); err != nil {
// 		return err
// 	}
// 	if dec.Type != nil {
// 		c.Type = *dec.Type
// 	}
// 	if dec.From != nil {
// 		c.From = *dec.From
// 	}
// 	if dec.Gas != nil {
// 		c.Gas = uint64(*dec.Gas)
// 	}
// 	if dec.GasUsed != nil {
// 		c.GasUsed = uint64(*dec.GasUsed)
// 	}
// 	if dec.To != nil {
// 		c.To = dec.To
// 	}
// 	if dec.Input != nil {
// 		c.Input = *dec.Input
// 	}
// 	if dec.Output != nil {
// 		c.Output = *dec.Output
// 	}
// 	if dec.Error != nil {
// 		c.Error = *dec.Error
// 	}
// 	if dec.RevertReason != nil {
// 		c.RevertReason = *dec.RevertReason
// 	}
// 	if dec.Calls != nil {
// 		c.Calls = dec.Calls
// 	}
// 	if dec.Logs != nil {
// 		c.Logs = dec.Logs
// 	}
// 	if dec.Value != nil {
// 		c.Value = (*big.Int)(dec.Value)
// 	}
// 	return nil
// }
