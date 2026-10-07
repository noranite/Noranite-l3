package server

const (
	DefaultEngineBatchSize         = 128
	pooledContainerRetentionFactor = 2
)

func pooledContainerCapacityLimit(batchSize int) int {
	if batchSize <= 0 {
		return 0
	}
	maxInt := int(^uint(0) >> 1)
	if batchSize > maxInt/pooledContainerRetentionFactor {
		return maxInt
	}
	return batchSize * pooledContainerRetentionFactor
}

// PacketBufferReleaser receives ownership of a packet buffer after an engine's
// final stage has finished using it. Once Put is called, previous owners must
// not access or reuse the slice unless they later reacquire it. The releaser may
// retain the buffer for later reuse.
//
// Put must be concurrency-safe. Server TX has one sequential sender per Peer,
// so different Peers may return buffers concurrently; RX delivery may also
// return buffers concurrently with TX.
type PacketBufferReleaser interface {
	Put([]byte)
}

// EngineErrorFunc reports asynchronous engine failures. It must be
// concurrency-safe: different per-Peer TX senders and the RX delivery worker may
// report at the same time.
type EngineErrorFunc func(error)
