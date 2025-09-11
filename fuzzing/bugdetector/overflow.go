package bugdetector

import (
	"fmt"

	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

func detect_overflow(tracer *BugDetectorTracer) {

	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]
	thisContract := lastCall.to

	if tracer.helperContract == thisContract {
		return
	}

	for point := range lastCall.overflowPoints {
		// fmt.Println("OVERFLOW detected at operation index:", point)

		id := fmt.Sprintf("OVERFLOW-%s-%d", thisContract.Hex(), point)

		tracer.bugMap.CoverBug(id)
	}
}

func is_overflow(op vm.OpCode, scope *vm.ScopeContext) bool {
	switch op {
	case vm.ADD:
		a := scope.Stack.Back(0)
		b := scope.Stack.Back(1)
		sum := new(uint256.Int).Add(a, b)
		if sum.Lt(a) || sum.Lt(b) {
			return true
		}
	case vm.SUB:
		a := scope.Stack.Back(0)
		b := scope.Stack.Back(1)
		if a.Lt(b) {
			return true
		}
	case vm.MUL:
		a := scope.Stack.Back(0)
		b := scope.Stack.Back(1)
		if a.IsZero() || b.IsZero() {
			return false
		} else {
			product := new(uint256.Int).Mul(a, b)
			if product.Lt(a) || product.Lt(b) {
				return true
			}
		}
	}

	return false
}
