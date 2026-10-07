package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	trafficMagic      uint32 = 0x4f4c3354 // "OL3T"
	trafficHeaderSize        = 16
	ipv4UDPOverhead          = 20 + 8
	defaultSocketBuf         = 16 << 20
	defaultBatchSize         = 64
	maxUDPPayload            = 65507
)

type result struct {
	Role           string  `json:"role"`
	Mode           string  `json:"mode,omitempty"`
	DurationMS     int64   `json:"duration_ms"`
	Packets        uint64  `json:"packets"`
	PayloadBytes   uint64  `json:"payload_bytes"`
	InnerIPv4Bytes uint64  `json:"inner_ipv4_bytes"`
	PPS            float64 `json:"pps"`
	InnerMbps      float64 `json:"inner_mbps"`
	TrackedPackets uint64  `json:"tracked_packets,omitempty"`
	OutOfOrder     uint64  `json:"out_of_order,omitempty"`
	SequenceGaps   uint64  `json:"sequence_gaps,omitempty"`
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "send":
		runSend(os.Args[2:])
	case "recv":
		runRecv(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s {send|recv} [flags]\n", os.Args[0])
	os.Exit(2)
}

func runSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	targetText := fs.String("target", "", "destination IPv4 UDP endpoint")
	bindText := fs.String("bind", "0.0.0.0:0", "source IPv4 UDP endpoint")
	mode := fs.String("mode", "fixed", "payload size mode: fixed, random, or zero")
	payloadSize := fs.Int("size", 1350, "fixed UDP payload size")
	minSize := fs.Int("min", trafficHeaderSize, "minimum random UDP payload size")
	maxSize := fs.Int("max", 1350, "maximum random UDP payload size")
	seed := fs.Int64("seed", 1, "deterministic random-size seed")
	duration := fs.Duration("duration", 15*time.Second, "send duration")
	batchSize := fs.Int("batch", defaultBatchSize, "sendmmsg batch size")
	socketBuffer := fs.Int("socket-buffer", defaultSocketBuf, "UDP write buffer request in bytes")
	_ = fs.Parse(args)

	if *duration <= 0 {
		log.Fatal("-duration must be positive")
	}
	if *batchSize <= 0 {
		log.Fatal("-batch must be positive")
	}
	target := mustAddrPort(*targetText, "target")
	bind := mustAddrPort(*bindText, "bind")

	sizeFor := payloadSizer(*mode, *payloadSize, *minSize, *maxSize, *seed)
	maxPayload := *payloadSize
	if *mode == "zero" {
		maxPayload = 0
	} else if *mode == "random" {
		maxPayload = *maxSize
	}
	if maxPayload < 0 || maxPayload > maxUDPPayload {
		log.Fatalf("maximum UDP payload %d is outside 0..%d", maxPayload, maxUDPPayload)
	}

	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(bind))
	if err != nil {
		log.Fatalf("listen UDP: %v", err)
	}
	defer conn.Close()
	if *socketBuffer > 0 {
		_ = conn.SetWriteBuffer(*socketBuffer)
	}
	packetConn := ipv4.NewPacketConn(conn)

	destination := net.UDPAddrFromAddrPort(target)
	buffers := make([][]byte, *batchSize)
	messages := make([]ipv4.Message, *batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, maxPayload)
		messages[i].Buffers = make([][]byte, 1)
		messages[i].Addr = destination
	}

	var packets, payloadBytes uint64
	var sequence uint64 = 1
	start := time.Now()
	deadline := start.Add(*duration)

	for time.Now().Before(deadline) {
		count := len(messages)
		batchBytes := uint64(0)
		for i := 0; i < count; i++ {
			size := sizeFor()
			buffer := buffers[i][:size]
			if size >= trafficHeaderSize {
				binary.BigEndian.PutUint32(buffer[0:4], trafficMagic)
				binary.BigEndian.PutUint64(buffer[4:12], sequence)
				binary.BigEndian.PutUint16(buffer[12:14], uint16(size))
				buffer[14] = 0
				buffer[15] = 0
			}
			messages[i].Buffers[0] = buffer
			batchBytes += uint64(size)
			sequence++
		}

		written := 0
		for written < count {
			n, err := packetConn.WriteBatch(messages[written:count], 0)
			if err != nil {
				log.Fatalf("write UDP batch: %v", err)
			}
			if n <= 0 {
				log.Fatal("write UDP batch made no progress")
			}
			written += n
		}
		packets += uint64(count)
		payloadBytes += batchBytes
	}

	elapsed := time.Since(start)
	printResult(makeResult("send", *mode, elapsed, packets, payloadBytes, 0, 0, 0))
}

func runRecv(args []string) {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	listenText := fs.String("listen", "0.0.0.0:9000", "listen IPv4 UDP endpoint")
	duration := fs.Duration("duration", 15*time.Second, "receive duration measured from first packet")
	startTimeout := fs.Duration("start-timeout", 15*time.Second, "time to wait for the first packet")
	batchSize := fs.Int("batch", defaultBatchSize, "recvmmsg batch size")
	socketBuffer := fs.Int("socket-buffer", defaultSocketBuf, "UDP read buffer request in bytes")
	_ = fs.Parse(args)

	if *duration <= 0 || *startTimeout <= 0 {
		log.Fatal("-duration and -start-timeout must be positive")
	}
	if *batchSize <= 0 {
		log.Fatal("-batch must be positive")
	}
	listen := mustAddrPort(*listenText, "listen")

	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(listen))
	if err != nil {
		log.Fatalf("listen UDP: %v", err)
	}
	defer conn.Close()
	if *socketBuffer > 0 {
		_ = conn.SetReadBuffer(*socketBuffer)
	}
	packetConn := ipv4.NewPacketConn(conn)

	buffers := make([][]byte, *batchSize)
	messages := make([]ipv4.Message, *batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, maxUDPPayload)
		messages[i].Buffers = [][]byte{buffers[i]}
	}

	if err := conn.SetReadDeadline(time.Now().Add(*startTimeout)); err != nil {
		log.Fatalf("set first-packet deadline: %v", err)
	}

	var packets, payloadBytes uint64
	var tracked, outOfOrder, sequenceGaps uint64
	var highestSequence uint64
	var started time.Time
	var deadline time.Time

	for {
		n, err := packetConn.ReadBatch(messages, 0)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if started.IsZero() {
					log.Fatal("timed out waiting for first UDP packet")
				}
				break
			}
			log.Fatalf("read UDP batch: %v", err)
		}
		if n <= 0 {
			continue
		}

		if started.IsZero() {
			started = time.Now()
			deadline = started.Add(*duration)
			if err := conn.SetReadDeadline(deadline); err != nil {
				log.Fatalf("set receive deadline: %v", err)
			}
		}

		for i := 0; i < n; i++ {
			size := messages[i].N
			if size < 0 || size > len(buffers[i]) {
				continue
			}
			packets++
			payloadBytes += uint64(size)
			if size >= trafficHeaderSize {
				packet := buffers[i][:size]
				if binary.BigEndian.Uint32(packet[0:4]) == trafficMagic &&
					int(binary.BigEndian.Uint16(packet[12:14])) == size {
					tracked++
					sequence := binary.BigEndian.Uint64(packet[4:12])
					if highestSequence != 0 {
						if sequence <= highestSequence {
							outOfOrder++
						} else if sequence > highestSequence+1 {
							sequenceGaps += sequence - highestSequence - 1
						}
					}
					if sequence > highestSequence {
						highestSequence = sequence
					}
				}
			}
		}
	}

	printResult(makeResult("recv", "", *duration, packets, payloadBytes, tracked, outOfOrder, sequenceGaps))
}

func payloadSizer(mode string, fixedSize, minSize, maxSize int, seed int64) func() int {
	switch mode {
	case "zero":
		return func() int { return 0 }
	case "fixed":
		if fixedSize < 0 || fixedSize > maxUDPPayload {
			log.Fatalf("-size must be in 0..%d", maxUDPPayload)
		}
		return func() int { return fixedSize }
	case "random":
		if minSize < 0 || maxSize < minSize || maxSize > maxUDPPayload {
			log.Fatalf("random payload range must satisfy 0 <= min <= max <= %d", maxUDPPayload)
		}
		rng := rand.New(rand.NewSource(seed))
		width := maxSize - minSize + 1
		return func() int { return minSize + rng.Intn(width) }
	default:
		log.Fatalf("unknown -mode %q", mode)
		return nil
	}
}

func mustAddrPort(text, name string) netip.AddrPort {
	addr, err := netip.ParseAddrPort(text)
	if err != nil {
		log.Fatalf("parse -%s %q: %v", name, text, err)
	}
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	if !addr.Addr().Is4() {
		log.Fatalf("-%s must be an IPv4 endpoint: %s", name, text)
	}
	if name == "target" && addr.Port() == 0 {
		log.Fatalf("-%s must use a non-zero port: %s", name, text)
	}
	return addr
}

func makeResult(
	role string,
	mode string,
	duration time.Duration,
	packets uint64,
	payloadBytes uint64,
	tracked uint64,
	outOfOrder uint64,
	sequenceGaps uint64,
) result {
	seconds := duration.Seconds()
	innerBytes := payloadBytes + packets*ipv4UDPOverhead
	var pps, innerMbps float64
	if seconds > 0 {
		pps = float64(packets) / seconds
		innerMbps = float64(innerBytes*8) / seconds / 1_000_000
	}
	return result{
		Role:           role,
		Mode:           mode,
		DurationMS:     duration.Milliseconds(),
		Packets:        packets,
		PayloadBytes:   payloadBytes,
		InnerIPv4Bytes: innerBytes,
		PPS:            pps,
		InnerMbps:      innerMbps,
		TrackedPackets: tracked,
		OutOfOrder:     outOfOrder,
		SequenceGaps:   sequenceGaps,
	}
}

func printResult(value result) {
	encoded, err := json.Marshal(value)
	if err != nil {
		log.Fatalf("encode result: %v", err)
	}
	fmt.Println(string(encoded))
}
