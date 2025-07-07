package rpc

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type contractInfoJSON struct {
	SourceCode      string `json:SourceCode`
	CompilerVersion string `json:"CompilerVersion"`
	ContractName    string `json:"ContractName"`
	Abi             string `json:"ABI"`
	Proxy           string `json:"Proxy"`
	Implementation  string `json:"Implementation"`
}

type MultipleSourceCode struct {
	Language string `json:"language"`
	Sources  map[string]map[string]string
}

type ContractInfo struct {
	Address          string `json:"address"`
	CompilerVersion  string `json:"compilerVersion"`
	ContractName     string `json:"contractName"`
	ContractPath     string `json:"contractPath"`
	MainContractPath string `json:"mainContractPath"`
	Abi              string `json:"abi"`
	Proxy            bool   `json:"Proxy"`
	Implementation   string `json:"Implementation"`
}

func GetContractSourceCode(address, cacheContractPath, apikey string) ([]*ContractInfo, error) {
	var err error
	url := fmt.Sprintf("https://api.etherscan.io/api?module=contract&action=getsourcecode&address=%s&apikey=%s", address, apikey)
	body, err := httpGet(url)
	if err != nil {
		return nil, fmt.Errorf("error in crawling contract: %v", err)
	}
	type etherscanResponse struct {
		Status  string             `json:"status"`
		Message string             `json:"message"`
		Result  []contractInfoJSON `json:"result"`
	}
	var res etherscanResponse
	err = json.Unmarshal([]byte(body), &res)
	if err != nil {
		// fmt.Println("Error unmarshaling JSON:", err)
		return nil, fmt.Errorf("error in parsing json: %v", err)
	}
	return parseContractSourceCodeResponse(address, res.Result)
	// return parseAndWriteContractOfAddress(fmt.Sprintf("%s/%s", cacheContractPath, strings.ToLower(address)), res.Result)
}

func parseContractSourceCodeResponse(address string, contracts []contractInfoJSON) ([]*ContractInfo, error) {
	var contractInfoList []*ContractInfo
	for _, c := range contracts {
		contractInfo := &ContractInfo{
			Address:         address,
			CompilerVersion: c.CompilerVersion,
			ContractName:    c.ContractName,
			Abi:             c.Abi,
		}
		if c.Proxy == "1" && c.Implementation != "" {
			contractInfo.Proxy = true
			contractInfo.Implementation = c.Implementation
		}
		contractInfoList = append(contractInfoList, contractInfo)
	}

	return contractInfoList, nil
}

func GetContractABI(address, apikey string) (string, error) {
	var err error
	url := fmt.Sprintf("https://api.etherscan.io/api?module=contract&action=getabi&address=%s&apikey=%s", address, apikey)
	body, err := httpGet(url)
	if err != nil {
		return "", fmt.Errorf("error in crawling contract: %v", err)
	}
	type etherscanResponse struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Result  any    `json:"result"`
	}
	var res etherscanResponse
	err = json.Unmarshal([]byte(body), &res)
	if err != nil {
		// fmt.Println("Error unmarshaling JSON:", err)
		return "", fmt.Errorf("error in parsing json: %v", err)
	}
	return res.Result.(string), nil
}

func parseAndWriteContractOfAddress(path string, contracts []contractInfoJSON) ([]*ContractInfo, error) {
	// fmt.Println("parseAndWriteContracts", path)
	os.MkdirAll(path, 0755)
	var contractInfoList []*ContractInfo
	for _, c := range contracts {
		var mainContractPath string
		if strings.HasPrefix(c.SourceCode, "{") {
			// multiple contracts
			var mSourceCode MultipleSourceCode
			err := json.Unmarshal([]byte(c.SourceCode[1:len(c.SourceCode)-1]), &mSourceCode)
			if err != nil {
				return nil, fmt.Errorf("error in parsing multiple contracts: %v", err)
			}
			if mSourceCode.Language != "Solidity" {
				return nil, fmt.Errorf("cannot handle the language other than Solidity")
			}
			for fileName := range mSourceCode.Sources {
				filePath := path + "/" + fileName
				parts := strings.Split(fileName, "/")
				if len(parts) > 1 {
					fileDirPath := path + "/" + strings.Join(parts[:len(parts)-1], "/")
					os.MkdirAll(fileDirPath, 0755)
				}
				err := ioutil.WriteFile(filePath, []byte(mSourceCode.Sources[fileName]["content"]), 0644)
				if err != nil {
					return nil, fmt.Errorf("error in writing contract in %v : %v", filePath, err)
				}
				if strings.Contains(mSourceCode.Sources[fileName]["content"], fmt.Sprintf("contract %s", c.ContractName)) {
					mainContractPath = filePath
				}
			}

		} else {
			filePath := fmt.Sprintf("%s/%s.sol", path, c.ContractName)
			mainContractPath = filePath
			err := ioutil.WriteFile(filePath, []byte(c.SourceCode), 0644)
			if err != nil {
				return nil, fmt.Errorf("error in writing contract in %v : %v", filePath, err)
			}
		}
		contractInfoList = append(contractInfoList, &ContractInfo{
			CompilerVersion:  c.CompilerVersion,
			ContractName:     c.ContractName,
			MainContractPath: mainContractPath,
			ContractPath:     path,
			Abi:              c.Abi,
		})
	}
	return contractInfoList, nil
}

func httpGet(url string) (string, error) {
	response, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status: %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// fmt.Println(string(body))
	return string(body), err
}
