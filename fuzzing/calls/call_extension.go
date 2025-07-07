package calls

import (
	"encoding/hex"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type InternalCall struct {
	IsUsed bool
	Depth  int
	Sender common.Address
	ToAddr common.Address
	Input  []byte
	Value  *big.Int
}

type InternalCallHookForReplay struct {
	internalCall *InternalCall
}

func NewInterCallHookForReplay(internalCall *InternalCall) *InternalCallHookForReplay {
	internalCall.IsUsed = false
	return &InternalCallHookForReplay{
		internalCall: internalCall,
	}
}

func (ichook *InternalCallHookForReplay) IsInternalCall(txOrigin, callee common.Address, depth int, input []byte) bool {
	if len(input) > 4 && hex.EncodeToString(input[:4]) == "e2dbeef4" {
		return false
	} else {
		if !ichook.internalCall.IsUsed && callee == ichook.internalCall.Sender && depth == ichook.internalCall.Depth {
			return true
		} else {
			return false
		}
	}
}

func (ichook *InternalCallHookForReplay) InternalCallHandler(callee common.Address, depth int) (common.Address, []byte, *big.Int) {
	ichook.internalCall.IsUsed = true
	return ichook.internalCall.ToAddr, ichook.internalCall.Input, ichook.internalCall.Value
}
