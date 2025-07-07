package coverage

import (
	"strings"

	"github.com/ethereum/go-ethereum/core/asm"
	"github.com/ethereum/go-ethereum/core/vm"
)

type InstrMap struct {
	Instructions []*Instruction
	PcToInstrs   map[uint64]*Instruction
}

type Instruction struct {
	Pc  uint64
	Op  vm.OpCode
	Arg []byte
}

func GetInstrMapFromBytecode(bytecode []byte) *InstrMap {
	instructions := make([]*Instruction, 0)
	pcToInstrs := make(map[uint64]*Instruction)

	it := asm.NewInstructionIterator(bytecode)
	for it.Next() {
		pc := it.PC()
		op := it.Op()
		arg := it.Arg()
		instr := &Instruction{
			Pc:  pc,
			Op:  op,
			Arg: arg,
		}
		instructions = append(instructions, instr)
		pcToInstrs[pc] = instr
	}
	if err := it.Error(); err != nil {
		// Ignore incomplete push instruction errors
		if !strings.HasPrefix(err.Error(), "incomplete push instruction") {
			return nil
		}
	}

	return &InstrMap{
		Instructions: instructions,
		PcToInstrs:   pcToInstrs,
	}
}
