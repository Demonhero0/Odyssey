package container

import (
	"container/list"
)

type HashLinkedList[K comparable, T any] struct {
	m    map[K]*list.Element
	list *list.List
}

type Node[K comparable, T any] struct {
	key   K
	value T
}

func NewHashLinkedList[K comparable, T any]() *HashLinkedList[K, T] {
	return &HashLinkedList[K, T]{
		m:    make(map[K]*list.Element),
		list: list.New(),
	}
}

// Append adds a new value with key to the hash linked list, if the key already exists, it updates the value
func (h *HashLinkedList[K, T]) Append(key K, value T) {
	if elem, exists := h.m[key]; exists {
		elem.Value.(*Node[K, T]).value = value
		return
	}
	node := &Node[K, T]{
		key:   key,
		value: value,
	}
	elem := h.list.PushBack(node)
	h.m[key] = elem
}

// Get returns the value of the key if it exists and a boolean indicating if it exists
func (h *HashLinkedList[K, T]) Get(key K) (T, bool) {
	if elem, exists := h.m[key]; exists {
		return elem.Value.(*Node[K, T]).value, true
	}
	var zero T // zero value of T
	return zero, false
}

// Remove deletes the key-value pair from the hash linked list
func (h *HashLinkedList[K, T]) Remove(key K) {
	if elem, exists := h.m[key]; exists {
		delete(h.m, key)
		h.list.Remove(elem)
	}
}

// Len returns the number of values in the hash linked list
func (h *HashLinkedList[K, T]) Len() int {
	return h.list.Len()
}

// Keys returns all keys in the order they were added
func (h *HashLinkedList[K, T]) Keys() []K {
	keys := make([]K, h.list.Len())
	for i, elem := 0, h.list.Front(); elem != nil; i, elem = i+1, elem.Next() {
		keys[i] = elem.Value.(*Node[K, T]).key
	}
	return keys
}

// Values returns all values in the order they were added
func (h *HashLinkedList[K, T]) Values() []T {
	values := make([]T, h.list.Len())
	for i, elem := 0, h.list.Front(); elem != nil; i, elem = i+1, elem.Next() {
		values[i] = elem.Value.(*Node[K, T]).value
	}
	return values
}
