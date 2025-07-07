package storagewrite

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

type StorageWriteSet struct {
	successSet  map[string]*StorageWrite
	revertedSet map[string]*StorageWrite
	lock        sync.RWMutex
}

func (ds *StorageWriteSet) TotalStorageWriteCount(includeReverted bool) int {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	count := len(ds.successSet)
	if includeReverted {
		for key, _ := range ds.revertedSet {
			if _, exists := ds.successSet[key]; !exists {
				count++
			}
		}
	}
	return count
}

// NewStorageWriteSet initializes a new StorageWriteSet object.
func NewStorageWriteSet() *StorageWriteSet {
	maps := &StorageWriteSet{}
	maps.Reset()
	return maps
}

// Reset clears the storage-write state for the StorageWriteSet.
func (ds *StorageWriteSet) Reset() {
	ds.successSet = make(map[string]*StorageWrite)
	ds.revertedSet = make(map[string]*StorageWrite)
}

// Update updates the current storage-write set with the provided ones.
// Returns two booleans indicating whether successful or reverted storage-write increased, or an error if one occurred.
func (ds *StorageWriteSet) Update(storageWriteSet *StorageWriteSet) (bool, bool, error) {
	// If our maps provided are nil, do nothing
	if storageWriteSet == nil {
		return false, false, nil
	}

	// Acquire our thread lock and defer our unlocking for when we exit this method
	ds.lock.Lock()
	defer ds.lock.Unlock()

	successUpdated := false
	revertedUpdated := false

	for key, storageWrite := range storageWriteSet.successSet {
		if _, exists := ds.successSet[key]; !exists {
			ds.successSet[key] = storageWrite
			successUpdated = true
		}
	}

	for key, storageWrite := range storageWriteSet.revertedSet {
		if _, exists := ds.revertedSet[key]; !exists {
			ds.revertedSet[key] = storageWrite
			revertedUpdated = true
		}
	}

	return successUpdated, revertedUpdated, nil
}

func (ds *StorageWriteSet) SetWrite(storageAddress common.Address, slot, val *uint256.Int, codeAddress common.Address, create bool, pc uint64) (bool, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	variable := &StorageSlot{
		Address: storageAddress,
		Slot:    slot,
		Value:   val,
	}
	position := &ProgramPosition{
		Address: codeAddress,
		Create:  create,
		Pc:      pc,
	}

	storageWrite := &StorageWrite{
		Position: position,
		Variable: variable,
	}
	storageWriteStr := storageWrite.String()
	if _, exists := ds.successSet[storageWriteStr]; !exists {
		ds.successSet[storageWriteStr] = storageWrite
		return true, nil
	}

	return false, nil
}

// RevertAll sets all storage-write in the set as reverted storage-write. Reverted storage-write set is
// updated with successful storage-write set, the successful storage-write set is cleared.
// Returns a boolean indicating whether reverted storage-write set increased, and an error if one occurred.
func (ds *StorageWriteSet) RevertAll() (bool, error) {
	// Acquire our thread lock and defer our unlocking for when we exit this method
	ds.lock.Lock()
	defer ds.lock.Unlock()

	// Define a variable to track if our reverted storage-write changed.
	revertedChanged := false

	for key, storageWrite := range ds.successSet {
		if _, exists := ds.revertedSet[key]; !exists {
			ds.revertedSet[key] = storageWrite
			revertedChanged = true
		}
	}
	ds.successSet = make(map[string]*StorageWrite)

	return revertedChanged, nil
}
