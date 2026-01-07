package invariant

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"

	// "github.com/dengsgo/math-engine/engine"
	engine "github.com/crytic/medusa/fuzzing/invariant/engine"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

type InvariantMaps struct {

	// maps represents a structure used to track every ContractCoverageMap by a given deployed address/lookup hash.
	maps map[string]*big.Int

	// scopeMaps records the variable
	scopeMaps map[string]*ScopeInvariant

	// varList and varMap record the variable name in order
	varList []string
	varMap  map[string]any
	// cachedVariableStrMap records the last value of variable
	// cachedVariableStrMap map[string]string
	// directionMap records the changed direction of variables
	directionMap map[string]direction

	// updateLock is a lock to offer concurrent thread safety for map accesses.
	updateLock sync.Mutex

	// for recording storage
	slotMap        map[common.Address]map[common.Hash]map[common.Hash]uint64
	updateSlotLock sync.Mutex

	// state guide config
	enabledNewScope bool
	// enabledStateConstruction bool
	enabledStateDivision  bool
	enabledStateDirection bool
}

type direction struct {
	changedValueList []*big.Int
	count            uint64
}

// NewInvariantMaps initializes a new NewInvariantMaps object.
func NewInvariantMaps() *InvariantMaps {
	maps := &InvariantMaps{}
	maps.Reset()
	return maps
}

var initUpdateBar uint64 = 6
var divisionPartNumber int = 6

func (im *InvariantMaps) InitInvariantMaps(
	enabledNewScope,
	// enabledStateConstruction,
	enabledStateDivision,
	enabledStateDirection bool,
	setInitUpdateBar uint64,
	setDivisionPartNumber int) {
	im.enabledNewScope = enabledNewScope
	// im.enabledStateConstruction = enabledStateConstruction
	im.enabledStateDivision = enabledStateDivision
	im.enabledStateDirection = enabledStateDirection

	initUpdateBar = setInitUpdateBar
	divisionPartNumber = setDivisionPartNumber
}

// Reset clears the coverage state for the InvariantMaps.
func (im *InvariantMaps) Reset() {
	im.maps = make(map[string]*big.Int)
	im.scopeMaps = make(map[string]*ScopeInvariant)
	im.slotMap = make(map[common.Address]map[common.Hash]map[common.Hash]uint64)
	im.varList = []string{}
	im.varMap = make(map[string]any)
	im.directionMap = make(map[string]direction)
	// im.cachedVariableStrMap = make(map[string]string)
	// im.hashedMaps = make(map[string][]string)
}

func (im *InvariantMaps) VariableValueMap() map[string]map[string]uint64 {
	im.updateLock.Lock()
	defer im.updateLock.Unlock()
	m := make(map[string]map[string]uint64)
	for name, scope := range im.scopeMaps {
		m[name] = make(map[string]uint64)
		for value, count := range scope.valueSet {
			m[name][value] = count
		}
	}
	return m
}

func (im *InvariantMaps) ShowScopeInvariants() {
	im.updateLock.Lock()
	defer im.updateLock.Unlock()
	fmt.Println("ShowScopeInvariants------------")
	for name, scope := range im.scopeMaps {
		// if scope.needShown {
		fmt.Printf("[%s]%s : [%s, %s], length = %d;\n", scope.source, name, scope.minValue, scope.maxValue, len(scope.valueSet))
		// scope.needShown = false
		// }
	}
	fmt.Println("ShowScopeInvariants------------")
}

type DumpState map[string]map[string]uint64

func (im *InvariantMaps) DumpState() DumpState {
	im.updateLock.Lock()
	defer im.updateLock.Unlock()
	s := make(DumpState)
	for name := range im.scopeMaps {
		s[name] = make(map[string]uint64)
		for value, count := range im.scopeMaps[name].valueSet {
			s[name][value] = count
		}
	}
	return s
}

func hashKeys(m map[string]*StateValue, kk []string) (string, []string) {
	if len(kk) > 0 {
		selectedKeys := make(map[string]any)
		for _, k := range kk {
			selectedKeys[k] = nil
		}

		keys := make([]string, 0, len(m))
		for k := range m {
			if _, exist := selectedKeys[k]; exist {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		return strings.Join(keys, ","), keys
	} else {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return strings.Join(keys, ","), keys
	}

}

func (im *InvariantMaps) UpdateState(stateVariables map[string]*StateValue) bool {

	// Acquire our thread lock and defer our unlocking for when we exit this method
	im.updateLock.Lock()
	defer im.updateLock.Unlock()

	flag := false
	for name, item := range stateVariables {
		_, isExist := im.scopeMaps[name]
		if !isExist {
			im.scopeMaps[name] = &ScopeInvariant{
				valueSet: make(map[string]uint64),
				source:   item.Source,
			}
		}

		isNewScope := false
		if item.Type == "uint256" {
			if im.enabledStateDivision {
				if im.scopeMaps[name].updateIntScopeInvariantWithStateDivision(item, !isExist) {
					isNewScope = true
				}
			} else {
				if im.scopeMaps[name].updateIntScopeInvariant(item, !isExist) {
					isNewScope = true
				}
			}
		} else {
			if im.scopeMaps[name].updateStrScopeInvariant(item, !isExist) {
				isNewScope = true
			}
		}
		if isNewScope {
			flag = true
			// for debug
			im.scopeMaps[name].needShown = true
		}
	}

	return flag && im.enabledNewScope
}

func (im *InvariantMaps) UpdateDirection(oldStateVariables, stateVariables map[string]*StateValue) (bool, string) {
	if oldStateVariables == nil {
		return false, ""
	}

	// Acquire our thread lock and defer our unlocking for when we exit this method
	im.updateLock.Lock()
	defer im.updateLock.Unlock()

	isExistNewStateValue := false
	for name := range stateVariables {
		if _, ok := im.varMap[name]; !ok {
			// if _, ok1 := selectedKeys[name]; ok1 {
			if stateVariables[name].Source == "sensitive" {
				im.varList = append(im.varList, name)
				im.varMap[name] = nil
				isExistNewStateValue = true
			}
		}
	}

	// deal with the existing direction in directionMap
	if isExistNewStateValue {
		for directionStr := range im.directionMap {
			newDirectionStr := directionStr + strings.Repeat("0", len(im.varList)-len(directionStr))
			if len(newDirectionStr) != len(im.varList) {
				panic("error in direction length")
			}
			im.directionMap[newDirectionStr] = im.directionMap[directionStr]
			delete(im.directionMap, directionStr)
		}
	}

	// isMoreBalance := false
	changedValueList := []*big.Int{}
	directionStr := ""
	for _, name := range im.varList {
		item := stateVariables[name]
		if item == nil {
			directionStr = directionStr + "0"
			changedValueList = append(changedValueList, big.NewInt(0))
		} else {
			d, value := im.extractVaribaleDirection(name, item, oldStateVariables)
			directionStr = directionStr + d
			changedValueList = append(changedValueList, value)

			// if name == "ether-sender" && d == ADDITION {
			// 	isMoreBalance = true
			// }
		}
	}

	flag := false
	if directionItem, ok := im.directionMap[directionStr]; !ok {
		im.directionMap[directionStr] = direction{
			changedValueList: append([]*big.Int{}, changedValueList...),
			count:            1,
		}
		flag = true
	} else {
		directionItem.count += 1
		for index, value := range changedValueList {
			if index >= len(directionItem.changedValueList) {
				directionItem.changedValueList = append(directionItem.changedValueList, big.NewInt(0))
			}
			if value.Cmp(directionItem.changedValueList[index]) == 1 {
				flag = true
				directionItem.changedValueList[index] = new(big.Int).Set(value)
			}
		}
		im.directionMap[directionStr] = directionItem
	}

	return flag && im.enabledStateDirection, directionStr
}

func (im *InvariantMaps) DirectionMap() map[string]uint64 {
	im.updateLock.Lock()
	defer im.updateLock.Unlock()
	m := make(map[string]uint64)
	for name, direction := range im.directionMap {
		m[name] = direction.count
	}
	return m
}

type ScopeInvariant struct {
	maxValue     *big.Int
	minValue     *big.Int
	valueSet     map[string]uint64
	touchedParts []*numberPart
	count        uint64
	updateBar    uint64

	// for debug
	needShown bool

	// for debug
	// newValueCount uint64
	source string
}

type numberPart struct {
	maxValue  *big.Int
	minValue  *big.Int
	isTouched bool
	count     uint64
}

func (si *ScopeInvariant) divideParts() error {

	if si.maxValue.Cmp(si.minValue) == -1 {
		return fmt.Errorf("cannot find the correct maxValue and minValue in divideParts")
	}

	si.touchedParts = []*numberPart{}
	si.touchedParts = append(si.touchedParts, &numberPart{
		minValue: new(big.Int).Sub(big.NewInt(0), abi.MaxUint256),
		maxValue: new(big.Int).Set(si.minValue),
		count:    0,
	})

	divisionNumber := divisionPartNumber
	if new(big.Int).Sub(si.maxValue, si.minValue).Cmp(big.NewInt(int64(divisionPartNumber))) < 0 {
		divisionNumber = int(new(big.Int).Sub(si.maxValue, si.minValue).Int64())
	}

	if divisionNumber > 0 {
		length := new(big.Int).Sub(si.maxValue, si.minValue)
		length = new(big.Int).Div(length, big.NewInt(int64(divisionNumber)))
		for i := 0; i < divisionNumber; i++ {
			if i < divisionNumber-1 {
				si.touchedParts = append(si.touchedParts, &numberPart{
					minValue: new(big.Int).Add(si.minValue, new(big.Int).Mul(length, big.NewInt(int64(i)))),
					maxValue: new(big.Int).Add(si.minValue, new(big.Int).Mul(length, big.NewInt(int64(i+1)))),
					count:    0,
				})
			} else {
				si.touchedParts = append(si.touchedParts, &numberPart{
					minValue: new(big.Int).Add(si.minValue, new(big.Int).Mul(length, big.NewInt(int64(i)))),
					maxValue: new(big.Int).Set(si.maxValue),
					count:    0,
				})
			}
		}
	}

	si.touchedParts = append(si.touchedParts, &numberPart{
		minValue: new(big.Int).Set(si.maxValue),
		maxValue: new(big.Int).Set(abi.MaxUint256),
		count:    0,
	})

	// taint the touched part after the first division
	if si.count > initUpdateBar {
		for valueStr, valueCount := range si.valueSet {
			value, _ := new(big.Int).SetString(valueStr, 10)
			for _, part := range si.touchedParts {
				if part.isContain(value) {
					part.count = valueCount
					part.isTouched = true
					break
				}
			}
		}
	}

	return nil
}

func (p *numberPart) isContain(value *big.Int) bool {
	return value.Cmp(p.minValue) == 1 && value.Cmp(p.maxValue) <= 0
}

func (scopeInvariant *ScopeInvariant) updateStrScopeInvariant(stateValue *StateValue, isNew bool) bool {

	valueStr, err := extractStrFromStateValue(stateValue)
	if err != nil {
		panic(err)
	}

	if isNew {
		scopeInvariant.valueSet[valueStr] = 0
		return true
	} else {
		flag := false
		if _, ok := scopeInvariant.valueSet[valueStr]; !ok {
			scopeInvariant.valueSet[valueStr] = 0
			flag = true
		}
		scopeInvariant.valueSet[valueStr] += 1
		return flag
	}
}

func (scopeInvariant *ScopeInvariant) updateIntScopeInvariant(stateValue *StateValue, isNew bool) bool {
	value := stateValue.Value.(*big.Int)
	if isNew {
		scopeInvariant.valueSet[value.String()] = 0
		return true
	} else {
		flag := false
		if _, ok := scopeInvariant.valueSet[value.String()]; !ok {
			scopeInvariant.valueSet[value.String()] = 0
			flag = true
		}
		scopeInvariant.valueSet[value.String()] += 1
		return flag
	}
}

func (scopeInvariant *ScopeInvariant) updateIntScopeInvariantWithStateDivision(stateValue *StateValue, isNew bool) bool {

	value := stateValue.Value.(*big.Int)

	if isNew {
		scopeInvariant.maxValue = new(big.Int).Set(value)
		scopeInvariant.minValue = new(big.Int).Set(value)
		scopeInvariant.count = 1
		scopeInvariant.updateBar = initUpdateBar
		scopeInvariant.valueSet[value.String()] = 1
		return false
	} else {
		// existing variable
		scopeInvariant.count += 1
		if value.Cmp(scopeInvariant.maxValue) == 1 {
			scopeInvariant.maxValue = new(big.Int).Set(value)
		}
		if value.Cmp(scopeInvariant.minValue) == -1 {
			scopeInvariant.minValue = new(big.Int).Set(value)
		}
		if _, ok := scopeInvariant.valueSet[value.String()]; !ok {
			scopeInvariant.valueSet[value.String()] = 0
		}
		scopeInvariant.valueSet[value.String()] += 1

		// check is new state
		isNewState := false
		if len(scopeInvariant.touchedParts) > 0 {
			for _, part := range scopeInvariant.touchedParts {
				if part.isContain(value) {
					part.count += 1
					isNewState = !part.isTouched
					part.isTouched = true
					break
				}
			}
		}

		if scopeInvariant.count == scopeInvariant.updateBar {
			scopeInvariant.divideParts()
			scopeInvariant.updateBar = scopeInvariant.updateBar * 2
		}
		return isNewState
	}
}

const (
	NOCHANGE  string = "0"
	CHANGE    string = "1"
	ADDITION  string = "2"
	REDUCTION string = "3"
)

func (im *InvariantMaps) extractVaribaleDirection(name string, stateValue *StateValue, oldStateVariables map[string]*StateValue) (string, *big.Int) {
	if stateValue.Type == "uint256" {
		value := stateValue.Value.(*big.Int)
		if _, ok := oldStateVariables[name]; !ok {
			return NOCHANGE, big.NewInt(0)
		} else {
			lastValue := oldStateVariables[name].Value.(*big.Int)
			if value.Cmp(lastValue) == 0 {
				return NOCHANGE, big.NewInt(0)
			} else if value.Cmp(lastValue) == 1 {
				return ADDITION, new(big.Int).Sub(value, lastValue)
			} else {
				return REDUCTION, new(big.Int).Sub(lastValue, value)
			}
		}
	} else {
		value, err := extractStrFromStateValue(stateValue)
		if err != nil {
			panic(err)
		}

		if _, ok := oldStateVariables[name]; !ok {
			return NOCHANGE, big.NewInt(0)
		} else {
			lastValue, err := extractStrFromStateValue(oldStateVariables[name])
			if err != nil {
				panic(err)
			}
			if lastValue == value {
				return NOCHANGE, big.NewInt(0)
			} else {
				return CHANGE, big.NewInt(1)
			}
		}
	}
}

func (im *InvariantMaps) UpdateSlots(slotMap map[common.Address]map[common.Hash]common.Hash) bool {
	// Acquire our thread lock and defer our unlocking for when we exit this method
	im.updateSlotLock.Lock()
	defer im.updateSlotLock.Unlock()
	flag := false
	for address := range slotMap {
		if _, ok := im.slotMap[address]; !ok {
			im.slotMap[address] = make(map[common.Hash]map[common.Hash]uint64)
		}
		for slot, value := range slotMap[address] {
			if _, ok := im.slotMap[address][slot]; !ok {
				im.slotMap[address][slot] = make(map[common.Hash]uint64)
			}
			if _, ok := im.slotMap[address][slot][value]; !ok {
				im.slotMap[address][slot][value] = 0
				flag = true
			}
			im.slotMap[address][slot][value] += 1
		}
	}
	return flag
}

func extractStrFromStateValue(stateValue *StateValue) (string, error) {
	var valueStr string
	switch stateValue.Type {
	case "bool":
		if stateValue.Value.(bool) {
			valueStr = "true"
		} else {
			valueStr = "false"
		}
	case "string":
		valueStr = stateValue.Value.(string)
	case "address":
		valueStr = stateValue.Value.(common.Address).String()
	case "fixedBytesTy":
		valueStr = hex.EncodeToString(stateValue.Value.([]byte))
	case "bytes":
		valueStr = hex.EncodeToString(stateValue.Value.([]byte))
	case "hash":
		valueStr = stateValue.Value.(common.Hash).String()
	default:
		return "", fmt.Errorf("unknown type")
	}
	return valueStr, nil
}

type DumpSlot map[string]map[string]uint64

func (im *InvariantMaps) DumpSlot() DumpSlot {
	im.updateSlotLock.Lock()
	defer im.updateSlotLock.Unlock()
	s := make(map[string]map[string]uint64)
	for address := range im.slotMap {
		for slot := range im.slotMap[address] {
			s[fmt.Sprintf("%s-%s", address.String(), slot.String())] = make(map[string]uint64)
			for value, count := range im.slotMap[address][slot] {
				s[fmt.Sprintf("%s-%s", address.String(), slot.String())][value.String()] = count
			}
		}
	}
	return s
}

// func (im *InvariantMaps) Update(checkerId string, newDistance *big.Int) bool {
// 	// Acquire our thread lock and defer our unlocking for when we exit this method
// 	im.updateLock.Lock()
// 	defer im.updateLock.Unlock()

// 	oriDistance, existOriDistance := im.maps[checkerId]
// 	if !existOriDistance {
// 		fmt.Println("init Distance", checkerId, oriDistance, newDistance)
// 		im.maps[checkerId] = new(big.Int).Add(newDistance, big.NewInt(0))
// 		return false
// 	} else if oriDistance.Cmp(big.NewInt(0)) >= 0 {
// 		tmpOriDistance := new(big.Int).Mul(oriDistance, big.NewInt(9))
// 		tmpNewDistance := new(big.Int).Mul(newDistance, big.NewInt(10))
// 		if tmpOriDistance.Cmp(tmpNewDistance) == 1 {
// 			fmt.Println("updateDistance", checkerId, oriDistance, newDistance)
// 			im.maps[checkerId] = new(big.Int).Set(newDistance)
// 			return true
// 		}
// 	}
// 	return false
// }

func (im *InvariantMaps) TotalScope() int {
	value, isExist := im.scopeMaps["0xA647ff3c36cFab592509E13860ab8c4F28781a66-rate()-0"]
	if isExist {
		return int(value.maxValue.Int64() - value.minValue.Int64())
		// return len(value.valueSet)
	} else {
		return 0
	}
}

func init() {
	// for calcuating distance of violating invariant
	engine.RegFunction("gt", 2, func(expr ...engine.ExprAST) *big.Int {
		if engine.ExprASTResult(expr[0]).Cmp(engine.ExprASTResult(expr[1])) == 1 {
			return new(big.Int).Sub(engine.ExprASTResult(expr[0]), engine.ExprASTResult(expr[1]))
		}
		return big.NewInt(-1)
	})
	engine.RegFunction("gte", 2, func(expr ...engine.ExprAST) *big.Int {
		if engine.ExprASTResult(expr[0]).Cmp(engine.ExprASTResult(expr[1])) >= 0 {
			return new(big.Int).Sub(engine.ExprASTResult(expr[0]), engine.ExprASTResult(expr[1]))
		}
		return big.NewInt(-1)
	})
	engine.RegFunction("lt", 2, func(expr ...engine.ExprAST) *big.Int {
		if engine.ExprASTResult(expr[0]).Cmp(engine.ExprASTResult(expr[1])) == -1 {
			return new(big.Int).Sub(engine.ExprASTResult(expr[1]), engine.ExprASTResult(expr[0]))
		}
		return big.NewInt(-1)
	})
	engine.RegFunction("lte", 2, func(expr ...engine.ExprAST) *big.Int {
		if engine.ExprASTResult(expr[0]).Cmp(engine.ExprASTResult(expr[1])) <= 0 {
			return new(big.Int).Sub(engine.ExprASTResult(expr[1]), engine.ExprASTResult(expr[0]))
		}
		return big.NewInt(-1)
	})
	engine.RegFunction("eq", 2, func(expr ...engine.ExprAST) *big.Int {
		if engine.ExprASTResult(expr[0]).Cmp(engine.ExprASTResult(expr[1])) == 0 {
			return big.NewInt(0)
		}
		return big.NewInt(-1)
	})
	engine.RegFunction("neq", 2, func(expr ...engine.ExprAST) *big.Int {
		if engine.ExprASTResult(expr[0]).Cmp(engine.ExprASTResult(expr[1])) != 0 {
			res := new(big.Int).Sub(engine.ExprASTResult(expr[0]), engine.ExprASTResult(expr[1]))
			return new(big.Int).Abs(res)
		}
		return big.NewInt(-1)
	})
	engine.RegFunction("or", -1, func(expr ...engine.ExprAST) *big.Int {
		if len(expr) == 0 {
			panic("error: and with no arg")
		}
		maxValue := new(big.Int).Set(engine.ExprASTResult(expr[0]))
		for _, e := range expr[1:] {
			res := engine.ExprASTResult(e)
			if res.Cmp(maxValue) > 0 {
				maxValue = new(big.Int).Set(res)
			}
		}
		return maxValue

		// if engine.ExprASTResult(expr[0]).Cmp(big.NewInt(0)) >= 0 || engine.ExprASTResult(expr[1]).Cmp(big.NewInt(0)) >= 0 {
		// 	if engine.ExprASTResult(expr[0]).Cmp(engine.ExprASTResult(expr[1])) == 1 {
		// 		return new(big.Int).Add(engine.ExprASTResult(expr[0]), big.NewInt(0))
		// 	} else {
		// 		return new(big.Int).Add(engine.ExprASTResult(expr[1]), big.NewInt(0))
		// 	}
		// }
		// return big.NewInt(-1)
	})
	engine.RegFunction("and", -1, func(expr ...engine.ExprAST) *big.Int {
		if len(expr) == 0 {
			panic("error: and with no arg")
		}
		minValue := new(big.Int).Set(engine.ExprASTResult(expr[0]))
		for _, e := range expr[1:] {
			res := engine.ExprASTResult(e)
			if res.Cmp(big.NewInt(0)) < 0 {
				return big.NewInt(-1)
			} else if res.Cmp(minValue) < 0 {
				minValue = new(big.Int).Set(res)
			}
		}
		return minValue

		// if engine.ExprASTResult(expr[0]).Cmp(big.NewInt(0)) >= 0 && engine.ExprASTResult(expr[1]).Cmp(big.NewInt(0)) >= 0 {
		// 	if engine.ExprASTResult(expr[0]).Cmp(engine.ExprASTResult(expr[1])) == -1 {
		// 		return new(big.Int).Add(engine.ExprASTResult(expr[0]), big.NewInt(0))
		// 	} else {
		// 		return new(big.Int).Add(engine.ExprASTResult(expr[1]), big.NewInt(0))
		// 	}
		// }
		// return big.NewInt(-1)
	})
	engine.RegFunction("cond", 3, func(expr ...engine.ExprAST) *big.Int {
		if engine.ExprASTResult(expr[0]).Cmp(big.NewInt(0)) >= 0 {
			return engine.ExprASTResult(expr[1])
		} else {
			return engine.ExprASTResult(expr[2])
		}
	})
}

func SolveInvariant(exp string) (*big.Int, error) {
	// input text -> []token
	var err error
	distance := big.NewInt(-1)
	toks, err := engine.Parse(exp)
	if err != nil {
		return distance, fmt.Errorf("solver error:%v", err.Error())
	}

	// []token -> AST Tree
	ast := engine.NewAST(toks, exp)
	if ast.Err != nil {
		return distance, fmt.Errorf("solver error:%v", ast.Err.Error())
	}
	// AST builder
	ar := ast.ParseExpression()
	if ast.Err != nil {
		return distance, fmt.Errorf("solver error:%v", ast.Err.Error())
	}
	// fmt.Printf("ExprAST: %+v\n", ar)
	// catch runtime errors
	defer func() {
		if e := recover(); e != nil {
			// fmt.Println("ERROR: ", e)
			err = fmt.Errorf("solver error:%v", e)
		}
	}()
	// AST traversal -> result
	distance = engine.ExprASTResult(ar)
	return distance, err
}
