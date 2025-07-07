package fuzzing

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strings"

	"github.com/crytic/medusa/utils/rpc"
	"github.com/ethereum/go-ethereum/common"
)

type CacheData struct {
	// ProxyContractMap map[common.Address]common.Address
	// AccountStateObject state.AccountStateObject
	ContractInfoMap map[string]*rpc.ContractInfo
}

const cachePath string = "tmp_cacheData"

// testAddress := common.HexToAddress("0x0000000000000000000000000000000000100000")
// balance, _ := new(big.Int).SetString("10000000000000000000", 10)
// hexStr := "6080604052600436106100345760003560e01c806327e235e314610039578063d0e30db014610078578063f940e38514610082575b600080fd5b34801561004557600080fd5b50610066610054366004610161565b60006020819052908152604090205481565b60405190815260200160405180910390f35b6100806100a2565b005b34801561008e57600080fd5b5061008061009d366004610183565b6100c8565b33600090815260208190526040812080543492906100c19084906101b6565b9091555050565b6001600160a01b0382811660009081526020819052604080822054905192841692909181818185875af1925050503d8060008114610122576040519150601f19603f3d011682016040523d82523d6000602084013e610127565b606091505b505050506001600160a01b0316600090815260208190526040812055565b80356001600160a01b038116811461015c57600080fd5b919050565b60006020828403121561017357600080fd5b61017c82610145565b9392505050565b6000806040838503121561019657600080fd5b61019f83610145565b91506101ad60208401610145565b90509250929050565b808201808211156101d757634e487b7160e01b600052601160045260246000fd5b9291505056fea26469706673582212204d6683c7c66d4e434f550ba9b2193bf97a39e84e357b16bd1f4be979f3125d5c64736f6c63430008190033"
// testCode, _ := hex.DecodeString(hexStr)
// fuzzer.fuzzerInitAccountState.initAccountState.InitAccountState.UpdateTouchedCode(testAddress, testCode)
// fuzzer.fuzzerInitAccountState.initAccountState.TraceAccountState.UpdateTouchedCode(testAddress, testCode)
// fuzzer.fuzzerInitAccountState.initAccountState.InitAccountState.UpdateTouchedBalance(testAddress, balance)
// fuzzer.fuzzerInitAccountState.initAccountState.TraceAccountState.UpdateTouchedBalance(testAddress, balance)

func (f *Fuzzer) loadInitialState() error {

	path := f.config.Fuzzing.OnChainFuzzingConfig.InitialStatePath
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	type sstate struct {
		Balance *big.Int                    `json:"balance"`
		Nonce   uint64                      `json:"nonce"`
		Code    string                      `json:"code"`
		Storage map[common.Hash]common.Hash `json:"storage"`
	}

	var data map[common.Address]sstate
	err = json.Unmarshal(bytes, &data)
	if err != nil {
		return err
	}

	for address, s := range data {
		f.fuzzerInitAccountState.initAccountState.InitAccountState.UpdateTouchedBalance(address, s.Balance)
		tmpCode, err := hex.DecodeString(s.Code)
		if err != nil {
			return err
		}
		f.fuzzerInitAccountState.initAccountState.InitAccountState.UpdateTouchedCode(address, tmpCode)
		f.fuzzerInitAccountState.initAccountState.InitAccountState.UpdateTouchedNonce(address, s.Nonce)
		for key, value := range s.Storage {
			f.fuzzerInitAccountState.initAccountState.InitAccountState.UpdateTouchedStorage(address, key, value)
		}
	}
	f.fuzzerInitAccountState.initAccountState.TraceAccountState = f.fuzzerInitAccountState.initAccountState.InitAccountState.DeepCopy()

	return nil
}

func (f *Fuzzer) getContractInfo(address string) (*rpc.ContractInfo, error) {
	address = strings.ToLower(address)
	contractInfo := &rpc.ContractInfo{}
	contractInfoPath := fmt.Sprintf("%s/%s_contractInfo.json", cachePath, address)
	isExistFile := true
	if _, err := os.Stat(contractInfoPath); os.IsNotExist(err) {
		isExistFile = false
	} else if err != nil {
		isExistFile = false
	}

	// existing file
	if isExistFile {
		file, err := os.Open(contractInfoPath)
		if err != nil {
			fmt.Println("Error:", err)
			return contractInfo, err
		}
		defer file.Close()

		bytes, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println("Error:", err)
			return contractInfo, err
		}

		err = json.Unmarshal(bytes, &contractInfo)
		if err != nil {
			// fmt.Println("Error:", err)
			return nil, err
		}
	} else {
		// abiString, err := rpc.GetContractABI(targetAddress, f.config.Fuzzing.OnChainFuzzingConfig.EtherscanApiKey)
		contractInfoList, err := rpc.GetContractSourceCode(address, "", f.config.Fuzzing.OnChainFuzzingConfig.EtherscanApiKey)
		if err != nil {
			return nil, err
		}
		if len(contractInfoList) != 1 {
			return nil, fmt.Errorf("cannot handle more than one contractInfo")
		}

		contractInfo = contractInfoList[0]
		f.dumpContractInfo(contractInfo)
	}
	return contractInfo, nil
}

func (f *Fuzzer) dumpContractInfo(contractInfo *rpc.ContractInfo) error {
	address := strings.ToLower(contractInfo.Address)
	contractInfoPath := fmt.Sprintf("%s/%s_contractInfo.json", cachePath, address)
	file, err := os.Create(contractInfoPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(contractInfo)
	if err != nil {
		return err
	}
	return nil
}

func (f *Fuzzer) loadCacheData() (*CacheData, error) {
	data := CacheData{
		ContractInfoMap: make(map[string]*rpc.ContractInfo),
	}

	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return &data, nil
	} else if err != nil {
		return &data, err
	}

	file, err := os.Open(cachePath)
	if err != nil {
		fmt.Println("Error:", err)
		return &data, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println("Error:", err)
		return &data, err
	}

	err = json.Unmarshal(bytes, &data)
	if err != nil {
		// fmt.Println("Error:", err)
		return &data, err
	}

	// for proxy, contract := range data.ProxyContractMap {
	// 	f.proxyContractMap[proxy] = contract
	// }

	// f.fuzzerInitAccountState.initAccountState.InitAccountState = data.AccountStateObject.DeepCopy()
	// f.fuzzerInitAccountState.initAccountState.TraceAccountState = data.AccountStateObject.DeepCopy()
	return &data, nil
}

func (f *Fuzzer) dumpCacheData(data *CacheData) {

	// data := CacheData{
	// ProxyContractMap: make(map[common.Address]common.Address),
	// AccountStateObject: *f.fuzzerInitAccountState.initAccountState.InitAccountState,
	// 	ContractInfoMap: make(map[string]*rpc.ContractInfo),
	// }

	// for proxy, contract := range f.proxyContractMap {
	// 	data.ProxyContractMap[proxy] = contract
	// }

	file, err := os.Create(cachePath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(data)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
}
