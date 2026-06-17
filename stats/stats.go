package stats

import "sync/atomic"

var (
	RequestsSent atomic.Int64
	BytesSent    atomic.Int64
)

func AddRequest(n int64) { RequestsSent.Add(n) }
func AddBytes(n int64)   { BytesSent.Add(n) }

func Reset() {
	RequestsSent.Store(0)
	BytesSent.Store(0)
}

func Snapshot() (reqs, bytes int64) {
	return RequestsSent.Load(), BytesSent.Load()
}
