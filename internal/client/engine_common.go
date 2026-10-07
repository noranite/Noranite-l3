package client

const DefaultEngineBatchSize = 128

// PacketBufferReleaser receives ownership of a packet buffer after the engine's
// sequential stage has finished using it. Once Put is called, previous owners
// must not access or reuse the slice unless they later reacquire it. The releaser
// may retain the buffer for later reuse.
type PacketBufferReleaser interface {
	Put([]byte)
}

// EngineErrorFunc reports asynchronous engine failures. Calls are serialized
// by each engine's sequential consumer.
type EngineErrorFunc func(error)
