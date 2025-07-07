package branchcoverage

import (
	"strings"

	"github.com/ethereum/go-ethereum/core/asm"
	"github.com/ethereum/go-ethereum/core/vm"
)

type BranchMap struct {
	BranchIds map[uint64]int // pc -> false branch id, true branch id = false branch id + 1
}

func (bm *BranchMap) Size() int {
	return len(bm.BranchIds) * 2
}

func (bm *BranchMap) GetBranchId(pc uint64, cond bool) int {
	branchId := bm.BranchIds[pc]
	if cond {
		branchId += 1
	}
	return branchId
}

func GetBranchMapFromBytecode(bytecode []byte) *BranchMap {
	branchIds := make(map[uint64]int)
	id := 0

	it := asm.NewInstructionIterator(bytecode)

	for it.Next() {
		if it.Op() == vm.JUMPI {
			branchIds[it.PC()] = id
			id += 2
		}
	}
	if err := it.Error(); err != nil {
		// Ignore incomplete push instruction errors
		if !strings.HasPrefix(err.Error(), "incomplete push instruction") {
			return nil
		}
	}

	return &BranchMap{
		BranchIds: branchIds,
	}
}
