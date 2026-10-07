//go:build linux

package prototype

import "testing"

func TestRuntimePacketPoolWithCapacityPreservesLogicalLength(t *testing.T) {
	const (
		bufferSize     = 1500
		bufferCapacity = 4096
	)

	pool := newRuntimePacketPoolWithCapacity(bufferSize, bufferCapacity, 1)
	buffer := pool.Get()
	if len(buffer) != bufferSize {
		t.Fatalf("buffer length = %d, want %d", len(buffer), bufferSize)
	}
	if cap(buffer) != bufferCapacity {
		t.Fatalf("buffer capacity = %d, want %d", cap(buffer), bufferCapacity)
	}

	pool.Put(buffer[:1])
	buffer = pool.Get()
	if len(buffer) != bufferSize {
		t.Fatalf("reused buffer length = %d, want %d", len(buffer), bufferSize)
	}
	if cap(buffer) != bufferCapacity {
		t.Fatalf("reused buffer capacity = %d, want %d", cap(buffer), bufferCapacity)
	}
}

func TestRuntimeGROPacketPoolKeepsWireLengthBounded(t *testing.T) {
	const bufferSize = 1500

	pool := newRuntimeGROPacketPool(bufferSize, 1)
	buffer := pool.Get()
	if len(buffer) != bufferSize {
		t.Fatalf("GRO buffer length = %d, want %d", len(buffer), bufferSize)
	}
	if cap(buffer) < runtimeTUNGROBackingCapacity {
		t.Fatalf(
			"GRO buffer capacity = %d, want at least %d",
			cap(buffer),
			runtimeTUNGROBackingCapacity,
		)
	}
}

func TestRuntimeGROPacketPoolHandlesLargerLogicalBuffer(t *testing.T) {
	const bufferSize = runtimeTUNGROBackingCapacity + 1024

	pool := newRuntimeGROPacketPool(bufferSize, 1)
	buffer := pool.Get()
	if len(buffer) != bufferSize {
		t.Fatalf("GRO buffer length = %d, want %d", len(buffer), bufferSize)
	}
	if cap(buffer) != bufferSize {
		t.Fatalf("GRO buffer capacity = %d, want %d", cap(buffer), bufferSize)
	}
}

func TestRuntimePacketPoolRejectsTooSmallCapacity(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected constructor to reject backing capacity smaller than logical size")
		}
	}()

	_ = newRuntimePacketPoolWithCapacity(1500, 1499, 1)
}

func TestRuntimePacketPoolRejectsReturnedBufferWithTooSmallCapacity(t *testing.T) {
	pool := newRuntimePacketPoolWithCapacity(1500, 4096, 1)
	_ = pool.Get()

	defer func() {
		if recover() == nil {
			t.Fatal("expected Put to reject buffer with insufficient backing capacity")
		}
	}()

	pool.Put(make([]byte, 1500))
}

func TestRuntimePacketPoolTryGetDoesNotBlockWhenEmpty(t *testing.T) {
	pool := newRuntimePacketPool(64, 1)
	buffer, ok := pool.TryGet()
	if !ok || len(buffer) != 64 {
		t.Fatalf("first TryGet=(len=%d, ok=%v), want buffer/true", len(buffer), ok)
	}
	if buffer, ok := pool.TryGet(); ok || buffer != nil {
		t.Fatalf("empty TryGet=(%v, %v), want nil/false", buffer, ok)
	}
	pool.Put(make([]byte, 64))
	if buffer, ok := pool.TryGet(); !ok || len(buffer) != 64 {
		t.Fatalf("replenished TryGet=(len=%d, ok=%v), want buffer/true", len(buffer), ok)
	}
}
