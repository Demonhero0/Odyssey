package invariant

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// storageExtractor map
type StorageExtractor struct {
	storageLayout StorageLayout
	storageCache  map[common.Hash]CacheStateValueInfo
}

var storageExtractorMap map[string]StorageExtractor

func init() {
	storageExtractorMap = make(map[string]StorageExtractor)
}

func calMappingKey(key, slot common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(key.Bytes(), slot.Bytes()))
}

func callSlitherScript(output_path, sol_file_path, contract_path, slitherScriptPath string) (map[string]StorageLayout, error) {
	// version := "0.4.24"
	// contract_name := "TestToken"
	// output_path := "test2_storage.json"
	// sol_file := "test2.sol"
	// contract_path := "../"
	var storageLayoutMap map[string]StorageLayout
	// output_path = output_path + "/tmp_storageLayout.json"
	cmd := exec.Command("python3", slitherScriptPath, "--output_path", output_path, "--sol_file", sol_file_path, "--contract_path", contract_path)
	// fmt.Println(cmd.String())
	_, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error in executing slither command: %v", err)
	}
	storageLayoutMap, err = loadStorageLayout(output_path)
	if err != nil {
		return nil, err
	}
	return storageLayoutMap, nil
}

func loadStorageLayout(path string) (map[string]StorageLayout, error) {
	var storageLayoutMap map[string]StorageLayout
	// Read the compiled JSON file data
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not load slither's exported storage data at path '%s', error: %v", path, err)
	}

	// Parse the JSON
	err = json.Unmarshal(b, &storageLayoutMap)
	if err != nil {
		return nil, fmt.Errorf("could not parse slither's exported solc data, error: %v", err)
	}
	return storageLayoutMap, err
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)

	if err == nil {
		return true
	}

	if os.IsNotExist(err) {
		return false
	}

	return false
}

func InitStorageExtractor(outputPath, mainContractPath, contractRootPath, slitherScriptPath string) (bool, error) {
	var err error
	var isExist bool
	var storageLayoutMap map[string]StorageLayout
	outputPath = outputPath + "/tmp_storageLayout.json"
	// check existing storage layout
	if fileExists(outputPath) {
		storageLayoutMap, err = loadStorageLayout(outputPath)
		if err != nil {
			return false, err
		}
		isExist = true
	} else {
		// read the version of compilation
		type tmpCompileConfig struct {
			Version string `json:"solc_solcs_select"`
		}
		var config tmpCompileConfig
		b, err := os.ReadFile(contractRootPath + "/" + "crytic_compile.config.json")
		if err != nil {
			return false, fmt.Errorf("could not load crytic-compile's exported config at path '%s', error: %v", contractRootPath+"/"+"crytic_compile.config.json", err)
		}
		// Parse the JSON
		err = json.Unmarshal(b, &config)
		if err != nil {
			return false, fmt.Errorf("could not parse crytic-compile's exported config data, error: %v", err)
		}
		solcVersion := config.Version
		out, err := exec.Command("solc-select", "install", solcVersion).CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("error while executing `solc-select install`:\nOUTPUT:\n%s\nERROR: %s\n", string(out), err.Error())
		}
		out, err = exec.Command("solc-select", "use", solcVersion).CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("error while executing `solc-select use`:\nOUTPUT:\n%s\nERROR: %s\n", string(out), err.Error())
		}

		storageLayoutMap, err = callSlitherScript(outputPath, mainContractPath, contractRootPath, slitherScriptPath)
		if err != nil {
			return false, fmt.Errorf("error in calling slither script: %v", err)
		}
		isExist = false
	}
	for contractName := range storageLayoutMap {
		sourcePathAndContractName := mainContractPath + ":" + contractName
		storageExtractorMap[sourcePathAndContractName] = newStorageExtractor(storageLayoutMap[contractName])
	}
	return isExist, nil
}

func InitStorageExtractors(compilations []compilationTypes.Compilation, outputPath string, targetContracts []string, slitherScriptPath string, contract_path string) error {
	var err error
	combinedStorageLayoutMap := make(map[string]StorageLayout)
	targetContractMap := make(map[string]bool)
	for _, targetContract := range targetContracts {
		targetContractMap[targetContract] = true
	}
	for _, compilation := range compilations {
		for source, compiledSource := range compilation.Sources {
			// only deal with target
			contracts := compiledSource.Contracts
			// sourceToStorageExtraction := make(map[string]bool)
			isTargetSource := false
			for contractName := range contracts {
				if _, ok := targetContractMap[contractName]; ok {
					// sourceToStorageExtraction[contractName] = true
					isTargetSource = true
					break
				}
			}

			if isTargetSource {
				absolutePath, existAbsolutePath := compiledSource.Ast.(map[string]any)["absolutePath"]
				if !existAbsolutePath {
					continue
				}
				if contract_path == "" {
					contract_path = "./"
					_, isSuffix := strings.CutSuffix(source, absolutePath.(string))
					if !isSuffix {
						continue
					}
				}
				// fmt.Println(source, absolutePath, contract_path)
				storageLayoutMap, err := callSlitherScript(outputPath, absolutePath.(string), contract_path, slitherScriptPath)
				if err != nil {
					return fmt.Errorf("error in calling slither script: %v", err)
				}
				for contractName := range storageLayoutMap {
					sourcePathAndContractName := source + ":" + contractName
					combinedStorageLayoutMap[sourcePathAndContractName] = storageLayoutMap[contractName]
					storageExtractorMap[sourcePathAndContractName] = newStorageExtractor(storageLayoutMap[contractName])
				}
			}
		}
		// storageLayoutMap, err := fuzzerTypes.CallSlitherScript("crytic-export", platformConfig.GetTarget(), fuzzer.config.Fuzzing.VariableRecoverConfig.SlitherScriptPath)
	}
	// write combinedStorageLayoutMap
	b, _ := json.Marshal(combinedStorageLayoutMap)
	err = os.WriteFile(fmt.Sprintf("%s/combinedStorageLayout.json", outputPath), b, 0644)
	if err != nil {
		return fmt.Errorf("error in writing combinedStorageLayout.json: %v", err)
	}
	return nil
}

func getStorageExtractor(sourcePathAndContractName string) *StorageExtractor {
	if storageExtractor, ok := storageExtractorMap[sourcePathAndContractName]; ok {
		return &storageExtractor
	} else {
		return nil
	}
}

func newStorageExtractor(s StorageLayout) StorageExtractor {
	return StorageExtractor{
		storageLayout: s,
	}
}
