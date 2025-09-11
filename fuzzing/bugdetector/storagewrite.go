package bugdetector

import (
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

type StorageSlot struct {
	Address common.Address // contract address
	Slot    *uint256.Int
	Value   *uint256.Int
}

func (s *StorageSlot) SlotString() string {
	var sb strings.Builder

	sb.WriteString(s.Address.Hex())
	sb.WriteString(":")
	sb.WriteString(s.Slot.Hex())

	return sb.String()
}

type StorageOperation struct {
	Variable        *StorageSlot
	OperationIndexs []uint64
}

func (s *StorageOperation) String() string {
	var sb strings.Builder

	sb.WriteString(s.Variable.SlotString())

	return sb.String()
}

type StorageSet struct {
	successSet  map[string]*StorageOperation
	revertedSet map[string]*StorageOperation
	lock        sync.RWMutex
}

// NewStorageSet initializes a new StorageSet object.
func NewStorageSet() *StorageSet {
	maps := &StorageSet{}
	maps.Reset()
	return maps
}

// Reset clears the storage-write state for the StorageSet.
func (ds *StorageSet) Reset() {
	ds.successSet = make(map[string]*StorageOperation)
	ds.revertedSet = make(map[string]*StorageOperation)
}

// Update updates the current storage-write set with the provided ones.
// Returns two booleans indicating whether successful or reverted storage-write increased, or an error if one occurred.
func (ds *StorageSet) Update(storageSet *StorageSet) (bool, bool, error) {
	// If our maps provided are nil, do nothing
	if storageSet == nil {
		return false, false, nil
	}

	// Acquire our thread lock and defer our unlocking for when we exit this method
	ds.lock.Lock()
	defer ds.lock.Unlock()

	successUpdated := false
	revertedUpdated := false

	for key, StorageOperation := range storageSet.successSet {
		if _, exists := ds.successSet[key]; !exists {
			ds.successSet[key] = StorageOperation
			successUpdated = true
		}
	}

	for key, StorageOperation := range storageSet.revertedSet {
		if _, exists := ds.revertedSet[key]; !exists {
			ds.revertedSet[key] = StorageOperation
			revertedUpdated = true
		}
	}

	return successUpdated, revertedUpdated, nil
}

func (ds *StorageSet) SetReadOrWrite(storageAddress common.Address, slot, val *uint256.Int, codeAddress common.Address, create bool, index uint64) error {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	variable := &StorageSlot{
		Address: storageAddress,
		Slot:    slot,
		Value:   val,
	}

	storageOperationStr := variable.SlotString()
	if _, exists := ds.successSet[storageOperationStr]; !exists {
		ds.successSet[storageOperationStr] = &StorageOperation{
			Variable:        variable,
			OperationIndexs: []uint64{index},
		}
		return nil
	} else {
		ds.successSet[storageOperationStr].OperationIndexs = append(ds.successSet[storageOperationStr].OperationIndexs, index)
	}
	return nil
}

// RevertAll sets all storage-write in the set as reverted storage-write. Reverted storage-write set is
// updated with successful storage-write set, the successful storage-write set is cleared.
// Returns a boolean indicating whether reverted storage-write set increased, and an error if one occurred.
func (ds *StorageSet) RevertAll() (bool, error) {
	// Acquire our thread lock and defer our unlocking for when we exit this method
	ds.lock.Lock()
	defer ds.lock.Unlock()

	// Define a variable to track if our reverted storage-write changed.
	revertedChanged := false

	for key, StorageOperation := range ds.successSet {
		if _, exists := ds.revertedSet[key]; !exists {
			ds.revertedSet[key] = StorageOperation
			revertedChanged = true
		}
	}
	ds.successSet = make(map[string]*StorageOperation)

	return revertedChanged, nil
}
