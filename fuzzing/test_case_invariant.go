package fuzzing

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/crytic/medusa/fuzzing/calls"
	fuzzerTypes "github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/invariant"
	"github.com/crytic/medusa/logging"
	"github.com/crytic/medusa/logging/colors"
)

type InvariantCheckerFunc func(map[string]*invariant.StateValue) (string, *big.Int, string)

// InvariantTestCase describes a test being run by a InvariantTestCaseProvider.
type InvariantChecker struct {
	// status describes the status of the test case
	status TestCaseStatus
	// targetContract describes the target contract where the test case was found
	targetContract *fuzzerTypes.Contract
	// targetMethod describes the target method for the test case
	targetMethod string
	// callSequence describes the call sequence that broke the property
	callSequence *calls.CallSequence
	// propertyTestTrace describes the execution trace when running the callSequence
	InvariantTestTrace *invariant.ExecutionTrace
	InvariantPattern   *InvariantPattern
	ViolationCase      string
	// for on-chain fuzzing
	isOnChain     bool
	targetAddress string
}

type InvariantPattern struct {
	Level             string              `json:"level"`
	Method            string              `json:"method"`
	MsgVarNames       []string            `json:"msgVarNames"`
	InputVarNames     []string            `json:"inputVarNames"`
	OriStateVarNames  []string            `json:"oriStateVarNames"`
	PreStateVarNames  []string            `json:"preStateVarNames"`
	PostStateVarNames []string            `json:"postStateVarNames"`
	Format            string              `json:"format"`
	Str               string              `json:"str"`
	VarMethodMap      map[string][]string `json:"varMethodMap"`
}

// Status describes the TestCaseStatus used to define the current state of the test.
func (t *InvariantChecker) Status() TestCaseStatus {
	return t.status
}

// CallSequence describes the types.CallSequence of calls sent to the EVM which resulted in this TestCase result.
// This should be nil if the result is not related to the CallSequence.
func (t *InvariantChecker) CallSequence() *calls.CallSequence {
	return t.callSequence
}

// LogMessage obtains a buffer that represents the result of the InvariantTestCase. This buffer can be passed to a logger for
// console or file logging.
func (t *InvariantChecker) LogMessage() *logging.LogBuffer {
	// If the test failed, return a failure message.
	buffer := logging.NewLogBuffer()
	if t.Status() == TestCaseStatusFailed {
		buffer.Append(colors.RedBold, fmt.Sprintf("[%s] ", t.Status()), colors.Bold, t.Name(), colors.Reset, "\n")
		// buffer.Append(fmt.Sprintf("Invariant \"%s\" failed after the following call sequence:\n", t.targetContract.Name()))
		buffer.Append(colors.Bold, "[Call Sequence]", colors.Reset, "\n")
		buffer.Append(t.CallSequence().Log().Elements()...)

		// If an execution trace is attached then add it to the message
		if t.InvariantTestTrace != nil {
			buffer.Append(colors.Bold, "[Execution Trace]", colors.Reset, "\n")
			buffer.Append(t.InvariantTestTrace.Log().Elements()...)
		}
		return buffer
	}

	buffer.Append(colors.GreenBold, fmt.Sprintf("[%s] ", t.Status()), colors.Bold, t.Name(), colors.Reset)
	return buffer
}

// Message obtains a text-based printable message which describes the result of the PropertyTestCase.
func (t *InvariantChecker) Message() string {
	// Internally, we just call log message and convert it to a string. This can be useful for 3rd party apps
	return t.LogMessage().String()
}

// Name describes the name of the test case.
func (t *InvariantChecker) Name() string {
	var nameStr string
	if t.isOnChain {
		nameStr = fmt.Sprintf("Invariant Check: %s.%s:%s", t.targetAddress, t.targetMethod, t.InvariantPattern.Str)
	} else {
		nameStr = fmt.Sprintf("Invariant Check: %s.%s:%s", t.targetContract.Name(), t.targetMethod, t.InvariantPattern.Str)
	}
	if t.status == TestCaseStatusFailed {
		nameStr = nameStr + "; violation:" + t.ViolationCase
	}
	return nameStr
}

// ID obtains a unique identifier for a test result.
func (t *InvariantChecker) ID() string {
	if t.isOnChain {
		return strings.Replace(fmt.Sprintf("Invariant-%s-%s-%s", t.targetAddress, t.targetMethod, t.InvariantPattern.Str), "_", "-", -1)
	}
	return strings.Replace(fmt.Sprintf("Invariant-%s-%s-%s", t.targetContract.Name(), t.targetMethod, t.InvariantPattern.Str), "_", "-", -1)
}

func (t *InvariantChecker) getInvariantCheckerFunc() InvariantCheckerFunc {
	var varNames []string
	varNames = append(varNames, t.InvariantPattern.MsgVarNames...)
	varNames = append(varNames, t.InvariantPattern.InputVarNames...)
	for _, varName := range t.InvariantPattern.OriStateVarNames {
		varNames = append(varNames, fmt.Sprintf("ori(%s)", varName))
	}
	for _, varName := range t.InvariantPattern.PreStateVarNames {
		varNames = append(varNames, fmt.Sprintf("pre(%s)", varName))
	}
	for _, varName := range t.InvariantPattern.PostStateVarNames {
		varNames = append(varNames, fmt.Sprintf("post(%s)", varName))
	}

	format := t.InvariantPattern.Format
	return func(stateVariables map[string]*invariant.StateValue) (string, *big.Int, string) {
		// mergedStateVariables := invariant.GetVariables(callFrame)
		// flag, distance, formatStr := CheckInvariantUtil(mergedStateVariables, varNames, format)
		// return flag, distance, formatStr

		formatWithVar := format
		// fmt.Println(formatWithVar)
		var flag string
		existVarNum := 0
		for _, varName := range varNames {
			if _, ok := stateVariables[varName]; ok {
				varValueStr := stateVariables[varName].GetValueStr()
				varName = fmt.Sprintf("{%s}", varName)
				formatWithVar = strings.Replace(formatWithVar, varName, varValueStr, -1)
				existVarNum += 1
			} else {
				break
			}
		}

		// fmt.Println(formatWithVar)

		var err error
		distance := big.NewInt(-1)
		if existVarNum == len(varNames) {
			distance, err = invariant.SolveInvariant(formatWithVar)
			if err != nil || distance == nil {
				fmt.Println("Error in SolveInvariant ", err, distance, formatWithVar)
				return "none", distance, ""
			}
			if distance.Cmp(big.NewInt(0)) >= 0 {
				flag = "satisfication"
			} else {
				flag = "violation"
			}
		} else {
			flag = "none"
		}
		// fmt.Println(formatWithVar, distance)
		return flag, distance, formatWithVar
	}
}

func LoadInvariantsFromJson(path string) map[string]map[string]*InvariantPattern {
	var invariantJson map[string]map[string]*InvariantPattern

	file, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("LoadInvariantFromJson error:", err)
	}
	err = json.Unmarshal([]byte(file), &invariantJson)
	if err != nil {
		fmt.Println("Json to struct error:", err)
	}

	return invariantJson
}

func checkInvariant(p *InvariantPattern) (bool, error) {
	// check
	tmpFormat := p.Format
	var varNames []string
	varNames = append(varNames, p.MsgVarNames...)
	varNames = append(varNames, p.InputVarNames...)
	for _, varName := range p.OriStateVarNames {
		varNames = append(varNames, fmt.Sprintf("ori(%s)", varName))
	}
	for _, varName := range p.PreStateVarNames {
		varNames = append(varNames, fmt.Sprintf("pre(%s)", varName))
	}
	for _, varName := range p.PostStateVarNames {
		varNames = append(varNames, fmt.Sprintf("post(%s)", varName))
	}
	for _, varName := range varNames {
		varName = fmt.Sprintf("{%s}", varName)
		tmpFormat = strings.Replace(tmpFormat, varName, "0", -1)
	}
	_, err := invariant.SolveInvariant(tmpFormat)
	if err != nil {
		return false, fmt.Errorf("error in invariant format:%v", err)
	}
	return true, nil
}
