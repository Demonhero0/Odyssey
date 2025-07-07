package helpercontracts

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/crytic/medusa/compilation"
)

func InitHelperContractCompilation() *compilation.CompilationConfig {
	fmt.Println(os.Getwd())
	platformConfigJSON := []byte(`{"target": "/home/pc/disk1/sujzh3/SmartFuzz/smartfuzz/fuzzing/helpercontracts/contracts/helpercontract.sol","solcVersion": "0.8.26","exportDirectory": "","args": []}`)
	rawMsg := json.RawMessage(platformConfigJSON)
	compilation := compilation.CompilationConfig{
		Platform:       "crytic-compile",
		PlatformConfig: &rawMsg,
	}

	return &compilation
}
