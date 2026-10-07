package dataplane

import "testing"

// Global sinks prevent the compiler from discarding benchmark results.
var (
	benchmarkMask  [RouteSize]byte
	benchmarkBytes []byte
)

func BenchmarkRouteMask(b *testing.B) {
	routeKey, _, _ := testKeys()

	scratch, err := NewDataScratch(routeKey)
	if err != nil {
		b.Fatalf(
			"NewDataScratch: %v",
			err,
		)
	}

	var tag [TagSize]byte

	for i := range tag {
		tag[i] = byte(i)
	}

	b.ReportAllocs()
	b.SetBytes(TagSize)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Vary the input between iterations.
		tag[0] = byte(i)

		mask, err := scratch.routeMask(
			tag[:],
		)
		if err != nil {
			b.Fatalf(
				"routeMask: %v",
				err,
			)
		}

		benchmarkMask = mask
	}
}

func BenchmarkSeal64(b *testing.B) {
	benchmarkSeal(
		b,
		64,
		false,
	)
}

func BenchmarkSeal1400(b *testing.B) {
	benchmarkSeal(
		b,
		1400,
		false,
	)
}

func BenchmarkSealFixedPadding64(b *testing.B) {
	benchmarkSeal(
		b,
		64,
		true,
	)
}

func BenchmarkSealFixedPadding1400(b *testing.B) {
	benchmarkSeal(
		b,
		1400,
		true,
	)
}

func benchmarkSeal(
	b *testing.B,
	plaintextSize int,
	fixedPadding bool,
) {
	routeKey, c2s, s2c := testKeys()

	session, err := NewSession(
		0x71a24e9c5312bb19,
		c2s,
		s2c,
		0,
	)
	if err != nil {
		b.Fatalf(
			"NewSession: %v",
			err,
		)
	}

	// Create scratch once per benchmark worker.
	scratch, err := NewDataScratch(
		routeKey,
	)
	if err != nil {
		b.Fatalf(
			"NewDataScratch: %v",
			err,
		)
	}

	plaintext := make(
		[]byte,
		plaintextSize,
	)

	// Reuse one destination buffer throughout the benchmark.
	dst := make(
		[]byte,
		0,
		plaintextSize+MaxDataExpansion,
	)

	b.ReportAllocs()
	b.SetBytes(int64(plaintextSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var wire []byte
		var err error

		if fixedPadding {
			// Exclude random padding selection from the codec measurement.
			wire, _, err = session.sealToWithPadding(
				scratch,
				dst,
				plaintext,
				7,
			)
		} else {
			// Include random padding selection.
			wire, _, err = session.sealTo(
				scratch,
				dst,
				plaintext,
			)
		}

		if err != nil {
			b.Fatalf(
				"seal: %v",
				err,
			)
		}

		benchmarkBytes = wire
	}
}

func BenchmarkOpen64(b *testing.B) {
	benchmarkOpen(
		b,
		64,
	)
}

func BenchmarkOpen1400(b *testing.B) {
	benchmarkOpen(
		b,
		1400,
	)
}

func benchmarkOpen(
	b *testing.B,
	plaintextSize int,
) {
	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 0x71a24e9c5312bb19
	const sequence uint64 = 10

	client, err := NewSession(
		sessionID,
		c2s,
		s2c,
		sequence,
	)
	if err != nil {
		b.Fatalf(
			"NewSession(client): %v",
			err,
		)
	}

	server, err := NewSession(
		sessionID,
		s2c,
		c2s,
		0,
	)
	if err != nil {
		b.Fatalf(
			"NewSession(server): %v",
			err,
		)
	}

	txScratch, err := NewDataScratch(
		routeKey,
	)
	if err != nil {
		b.Fatalf(
			"NewDataScratch(TX): %v",
			err,
		)
	}

	rxScratch, err := NewDataScratch(
		routeKey,
	)
	if err != nil {
		b.Fatalf(
			"NewDataScratch(RX): %v",
			err,
		)
	}

	plaintext := make(
		[]byte,
		plaintextSize,
	)

	templateBuffer := make(
		[]byte,
		0,
		plaintextSize+MaxDataExpansion,
	)

	// Fixed padding produces a stable template datagram.
	templateWire, _, err := client.sealToWithPadding(
		txScratch,
		templateBuffer,
		plaintext,
		7,
	)
	if err != nil {
		b.Fatalf(
			"sealToWithPadding template: %v",
			err,
		)
	}

	// Open decrypts in-place.
	//
	// Restore ciphertext before each in-place decode.
	work := make(
		[]byte,
		len(templateWire),
	)

	b.ReportAllocs()
	b.SetBytes(int64(plaintextSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy(
			work,
			templateWire,
		)

		opened, err := server.AuthenticateInPlace(
			rxScratch,
			work,
			sequence,
		)
		if err != nil {
			b.Fatalf(
				"AuthenticateInPlace: %v",
				err,
			)
		}

		benchmarkBytes = opened
	}
}
