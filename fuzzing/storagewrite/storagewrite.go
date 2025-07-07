package storagewrite

import (
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

type ProgramPosition struct {
	Address common.Address // code address
	Create  bool           // whether Pc is in the init bytecode
	Pc      uint64
}

func (s *ProgramPosition) String() string {
	var sb strings.Builder

	sb.WriteString(s.Address.Hex())
	if s.Create {
		sb.WriteString("c")
	}
	sb.WriteString(":")
	sb.WriteString(strconv.FormatUint(s.Pc, 16))

	return sb.String()
}

type StorageSlot struct {
	Address common.Address // contract address
	Slot    *uint256.Int
	Value   *uint256.Int
}

func (s *StorageSlot) SlotString() string {
	var sb strings.Builder

	sb.WriteString(s.Address.Hex())
	sb.WriteString(":")
	sb.WriteString(s.Slot.Hex())

	return sb.String()
}

func (s *StorageSlot) String() string {
	var sb strings.Builder

	sb.WriteString(s.Address.Hex())
	sb.WriteString(":")
	sb.WriteString(s.Slot.Hex())
	sb.WriteString(":")
	sb.WriteString(s.Value.Hex())

	return sb.String()
}

type StorageWrite struct {
	Position *ProgramPosition
	Variable *StorageSlot
}

func (s *StorageWrite) String() string {
	var sb strings.Builder

	sb.WriteString(s.Position.String())
	sb.WriteString("-")
	sb.WriteString(s.Variable.String())

	return sb.String()
}
