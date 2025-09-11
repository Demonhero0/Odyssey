package bugdetector

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

type TokenTransfer struct {
	From   common.Address
	To     common.Address
	Token  common.Address
	Amount *uint256.Int
}
