package utils

import (
	"sync/atomic"
	"unsafe"
)

// RingBuffer is a lock-free, round-robin selector over a fixed slice.
// Useful for cycling through proxy lists or user-agents without mutex contention.
type RingBuffer[T any] struct {
	items []T
	idx   atomic.Uint64
	size  uint64
}

// NewRingBuffer creates a RingBuffer from items. Panics on empty slice.
func NewRingBuffer[T any](items []T) *RingBuffer[T] {
	if len(items) == 0 {
		panic("RingBuffer: empty items slice")
	}
	return &RingBuffer[T]{items: items, size: uint64(len(items))}
}

// Next returns the next item in round-robin order. Safe for concurrent use.
func (r *RingBuffer[T]) Next() T {
	idx := r.idx.Add(1) - 1
	return r.items[idx%r.size]
}

// Len returns the number of items in the ring.
func (r *RingBuffer[T]) Len() int { return len(r.items) }

// Reset atomically resets the ring to start from position 0.
func (r *RingBuffer[T]) Reset() { r.idx.Store(0) }

// Pointer-size assertion — ensures unsafe ops are valid on this platform.
var _ = unsafe.Sizeof(uintptr(0))
