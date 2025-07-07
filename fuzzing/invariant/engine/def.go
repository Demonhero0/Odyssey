package engine

import (
	"errors"
	"math/big"
)

const (
	RadianMode = iota
	AngleMode
)

type defS struct {
	argc int
	fun  func(expr ...ExprAST) *big.Int
}

// enum "RadianMode", "AngleMode"
// var TrigonometricMode = RadianMode

// var defConst = map[string]float64{
// "pi": math.Pi,
// }

var defFunc map[string]defS

func init() {
	defFunc = map[string]defS{

		"abs": {1, defAbs},

		"max": {-1, defMax},
		"min": {-1, defMin},
	}
}

// abs(-2) = 2
func defAbs(expr ...ExprAST) *big.Int {
	return new(big.Int).Abs(ExprASTResult(expr[0]))
}

// max(2) = 2
// max(2, 3) = 3
// max(2, 3, 1) = 3
func defMax(expr ...ExprAST) *big.Int {
	if len(expr) == 0 {
		panic(errors.New("calling function `max` must have at least one parameter."))
	}
	if len(expr) == 1 {
		return new(big.Int).Add(ExprASTResult(expr[0]), big.NewInt(0))
	}
	maxV := new(big.Int).Add(ExprASTResult(expr[0]), big.NewInt(0))
	for i := 1; i < len(expr); i++ {
		v := ExprASTResult(expr[i])
		if v.Cmp(maxV) == 1 {
			maxV = new(big.Int).Add(v, big.NewInt(0))
		}
	}
	return maxV
}

// min(2) = 2
// min(2, 3) = 2
// min(2, 3, 1) = 1
func defMin(expr ...ExprAST) *big.Int {
	if len(expr) == 0 {
		panic(errors.New("calling function `min` must have at least one parameter."))
	}
	if len(expr) == 1 {
		return new(big.Int).Add(ExprASTResult(expr[0]), big.NewInt(0))
	}
	minV := ExprASTResult(expr[0])
	for i := 1; i < len(expr); i++ {
		v := ExprASTResult(expr[i])
		if v.Cmp(minV) == 1 {
			minV = new(big.Int).Add(v, big.NewInt(0))
		}
	}
	return minV
}

// noerr(1/0) = 0
// noerr(2.5/(1-1)) = 0
// func defNoerr(expr ...ExprAST) (r float64) {
// 	defer func() {
// 		if e := recover(); e != nil {
// 			r = 0
// 		}
// 	}()
// 	return ExprASTResult(expr[0])
// }
