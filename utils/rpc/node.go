package rpc

import (
	"context"
	"log"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type NodeProvider struct {
	NodeURL   string
	Count     int
	countLock sync.Mutex
}

var Provider NodeProvider

func (p *NodeProvider) addCount() {
	p.countLock.Lock()
	p.Count += 1
	p.countLock.Unlock()
}

func (p *NodeProvider) GetStorageAt(account common.Address, key common.Hash, blockNumber *big.Int) (common.Hash, error) {
	// blockNumber = new(big.Int).Sub(blockNumber, big.NewInt(1))
	client, err := ethclient.Dial(p.NodeURL)
	if err != nil {
		log.Fatal(err)
	}

	value, err := client.StorageAt(context.Background(), account, key, blockNumber)
	// fmt.Println("GetStorageAt", hex.EncodeToString(value), err)
	p.addCount()
	return common.BytesToHash(value), err
}

func (p *NodeProvider) GetCodeAt(account common.Address, blockNumber *big.Int) ([]byte, error) {
	// blockNumber = new(big.Int).Sub(blockNumber, big.NewInt(1))
	client, err := ethclient.Dial(p.NodeURL)
	if err != nil {
		log.Fatal(err)
	}

	value, err := client.CodeAt(context.Background(), account, blockNumber)
	// fmt.Println("getCodeAt", account, len(value))
	p.addCount()
	return value, err
}

func (p *NodeProvider) GetNonceAt(account common.Address, blockNumber *big.Int) (uint64, error) {
	// blockNumber = new(big.Int).Sub(blockNumber, big.NewInt(1))
	client, err := ethclient.Dial(p.NodeURL)
	if err != nil {
		log.Fatal(err)
	}

	value, err := client.NonceAt(context.Background(), account, blockNumber)
	// fmt.Println("getNonceAt", account, value)
	p.addCount()
	return value, err
}

func (p *NodeProvider) GetBalanceAt(account common.Address, blockNumber *big.Int) (*big.Int, error) {
	// blockNumber = new(big.Int).Sub(blockNumber, big.NewInt(1))
	client, err := ethclient.Dial(p.NodeURL)
	if err != nil {
		log.Fatal(err)
	}

	value, err := client.BalanceAt(context.Background(), account, blockNumber)
	p.addCount()
	return value, err
}

func (p *NodeProvider) GetTransactionByHash(hash common.Hash) (tx *types.Transaction, isPending bool, err error) {
	client, err := ethclient.Dial(p.NodeURL)
	if err != nil {
		log.Fatal(err)
	}

	tx, isPending, err = client.TransactionByHash(context.Background(), hash)
	return tx, isPending, err
}

func (p *NodeProvider) GetTransactionReceipt(hash common.Hash) (txReceipt *types.Receipt, err error) {
	client, err := ethclient.Dial(p.NodeURL)
	if err != nil {
		log.Fatal(err)
	}

	txReceipt, err = client.TransactionReceipt(context.Background(), hash)
	return txReceipt, err
}

func (p *NodeProvider) GetBlockByNumber(number *big.Int) (block *types.Block, err error) {
	client, err := ethclient.Dial(p.NodeURL)
	if err != nil {
		log.Fatal(err)
	}

	block, err = client.BlockByNumber(context.Background(), number)
	return block, err
}

func (p *NodeProvider) GetHeaderByNumber(number *big.Int) (header *types.Header, err error) {
	client, err := ethclient.Dial(p.NodeURL)
	if err != nil {
		log.Fatal(err)
	}

	header, err = client.HeaderByNumber(context.Background(), number)
	return header, err
}
