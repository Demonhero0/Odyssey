package engine

import (
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// Top level function
// Analytical expression and execution
// err is not nil if an error occurs (including arithmetic runtime errors)
func ParseAndExec(s string) (r *big.Int, err error) {
	toks, err := Parse(s)
	if err != nil {
		return big.NewInt(0), err
	}
	ast := NewAST(toks, s)
	if ast.Err != nil {
		return big.NewInt(0), ast.Err
	}
	ar := ast.ParseExpression()
	if ast.Err != nil {
		return big.NewInt(0), ast.Err
	}
	defer func() {
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()
	return ExprASTResult(ar), err
}

func ErrPos(s string, pos int) string {
	r := strings.Repeat("-", len(s)) + "\n"
	s += "\n"
	for i := 0; i < pos; i++ {
		s += " "
	}
	s += "^\n"
	return r + s + r
}

// the integer power of a number
func Pow(x float64, n float64) float64 {
	return math.Pow(x, n)
}

// Float64ToStr float64 -> string
func Float64ToStr(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// RegFunction is Top level function
// register a new function to use in expressions
// name: be register function name. the same function name only needs to be registered once.
// argc: this is a number of parameter signatures. should be -1, 0, or a positive integer
//
//	-1 variable-length argument; >=0 fixed numbers argument
//
// fun:  function handler
func RegFunction(name string, argc int, fun func(...ExprAST) *big.Int) error {
	if len(name) == 0 {
		return errors.New("RegFunction name is not empty")
	}
	if argc < -1 {
		return errors.New("RegFunction argc should be -1, 0, or a positive integer")
	}
	if _, ok := defFunc[name]; ok {
		return errors.New("RegFunction name is already exist")
	}
	defFunc[name] = defS{argc, fun}
	return nil
}

// ExprASTResult is a Top level function
// AST traversal
// if an arithmetic runtime error occurs, a panic exception is thrown
func ExprASTResult(expr ExprAST) *big.Int {
	var l, r *big.Int
	switch expr.(type) {
	case BinaryExprAST:
		ast := expr.(BinaryExprAST)
		l = new(big.Int).Add(ExprASTResult(ast.Lhs), big.NewInt(0))
		r = new(big.Int).Add(ExprASTResult(ast.Rhs), big.NewInt(0))
		switch ast.Op {
		case "+":
			f := new(big.Int).Add(l, r)
			return f
		case "-":
			f := new(big.Int).Sub(l, r)
			return f
		case "*":
			f := new(big.Int).Mul(l, r)
			return f
		case "<":
			if ExprASTResult(ast.Lhs).Cmp(ExprASTResult(ast.Rhs)) == -1 {
				return new(big.Int).Sub(ExprASTResult(ast.Rhs), ExprASTResult(ast.Lhs))
			}
			return big.NewInt(-1)
		case ">":
			if ExprASTResult(ast.Lhs).Cmp(ExprASTResult(ast.Rhs)) == 1 {
				return new(big.Int).Sub(ExprASTResult(ast.Lhs), ExprASTResult(ast.Rhs))
			}
			return big.NewInt(-1)
		case "=":
			if ExprASTResult(ast.Lhs).Cmp(ExprASTResult(ast.Rhs)) == 0 {
				return big.NewInt(0)
			}
			return big.NewInt(-1)
		default:
			panic("error in ExprASTResult")
		}
	case NumberExprAST:
		return expr.(NumberExprAST).Val
	case FunCallerExprAST:
		f := expr.(FunCallerExprAST)
		def := defFunc[f.Name]
		return def.fun(f.Arg...)
	}

	return big.NewInt(0)
}
