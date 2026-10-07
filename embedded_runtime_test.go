package noranite

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	coreclient "github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/noisehandshake"
	coreserver "github.com/noranite/Noranite-l3/internal/server"
)

func TestClientWaitReadyBlocksWithoutEstablishedSession(t *testing.T) {
	device := newTestPacketDevice()
	transport, peer := net.Pipe()
	defer peer.Close()

	client, err := NewClient(testPublicClientConfig(t, DefaultMTU), device, transport)
	if err != nil {
		t.Fatal(err)
	}

	drainDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, peer)
		close(drainDone)
	}()

	runDone := make(chan error, 1)
	go func() { runDone <- client.Run(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := client.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitReady error=%v, want %v", err, context.DeadlineExceeded)
	}

	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("client.Close: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Client.Run returned after Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Client.Run did not stop after Close")
	}
	select {
	case <-drainDone:
	case <-time.After(2 * time.Second):
		t.Fatal("transport drain did not stop")
	}
}

func TestClientOfflineStartupThenTransportAvailable(t *testing.T) {
	device := newTestPacketDevice()
	client, err := NewClient(testPublicClientConfig(t, DefaultMTU), device, nil)
	if err != nil {
		t.Fatalf("NewClient without transport: %v", err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- client.Run(context.Background()) }()
	select {
	case err := <-runDone:
		t.Fatalf("Client.Run stopped while offline: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	transport, peer := net.Pipe()
	defer peer.Close()
	generation, err := client.ReplaceTransport(transport)
	if err != nil {
		t.Fatalf("ReplaceTransport after offline startup: %v", err)
	}
	if generation != 1 {
		t.Fatalf("replacement generation=%d, want 1", generation)
	}
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, dataplane.MaxGeneratedEstablishmentWirePacketSize)
	n, err := peer.Read(buffer)
	if err != nil {
		t.Fatalf("read establishment after transport availability: %v", err)
	}
	if n == 0 {
		t.Fatal("transport availability did not trigger establishment retry")
	}

	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("client.Close: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Client.Run returned after Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Client.Run did not stop after Close")
	}
}

func TestClientConstructsWithoutInitialTransport(t *testing.T) {
	device := newTestPacketDevice()
	client, err := NewClient(testPublicClientConfig(t, DefaultMTU), device, nil)
	if err != nil {
		t.Fatalf("NewClient without transport: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close disconnected client: %v", err)
	}
}

func TestClientConstructAndCloseBeforeRun(t *testing.T) {
	device := newTestPacketDevice()
	transport, peer := net.Pipe()
	defer peer.Close()

	var clientPrivate, serverPrivate [32]byte
	clientPrivate[0] = 1
	serverPrivate[0] = 2
	serverPublic, err := noisehandshake.PublicKeyFromPrivate(noisehandshake.PrivateKey(serverPrivate))
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(ClientConfig{
		TunnelIPv4:       netip.MustParseAddr("10.66.0.2"),
		ServerEndpoint:   netip.MustParseAddrPort("192.0.2.1:51820"),
		MTU:              DefaultMTU,
		RouteKey:         [32]byte{1},
		StaticPrivateKey: clientPrivate,
		ServerPublicKey:  [32]byte(serverPublic),
	}, device, transport)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	if err := client.Run(context.Background()); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Run after Close error=%v, want %v", err, ErrClientClosed)
	}
}

func TestEmbeddedRuntimeSinglePacketRoundTrip(t *testing.T) {
	clientIP := netip.MustParseAddr("10.66.0.2")
	serverIP := netip.MustParseAddr("10.66.0.1")
	outerServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer outerServer.Close()

	serverEndpoint := outerServer.LocalAddr().(*net.UDPAddr).AddrPort()
	transport, err := net.DialUDP("udp4", nil, outerServer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	var routeKey, c2s, s2c [32]byte
	for i := 0; i < 32; i++ {
		routeKey[i] = byte(i + 1)
		c2s[i] = byte(0x41 + i)
		s2c[i] = byte(0x81 + i)
	}

	const sessionID uint64 = 0x71a24e9c5312bb19
	clientSession, err := dataplane.NewSession(sessionID, c2s, s2c, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverSession, err := dataplane.NewSession(sessionID, s2c, c2s, 0)
	if err != nil {
		t.Fatal(err)
	}

	core, err := coreclient.New(coreclient.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: coreclient.LifecycleConfig{
			GenerationLifetime: 24 * time.Hour,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientSession,
	})
	if err != nil {
		t.Fatal(err)
	}

	device := newTestPacketDevice()
	runtime, err := newEmbeddedRuntime(
		device,
		transport,
		core,
		serverEndpoint,
		dataplane.ReferenceTunnelMTU,
	)
	if err != nil {
		t.Fatal(err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run() }()
	select {
	case <-runtime.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not become ready")
	}

	request := testIPv4Packet(clientIP, serverIP, 96)
	device.inject(request)

	outerServer.SetReadDeadline(time.Now().Add(2 * time.Second))
	wire := make([]byte, 2048)
	n, clientOuter, err := outerServer.ReadFromUDP(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire = wire[:n]

	serverScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatal(err)
	}
	route, err := dataplane.DecodeRoute(serverScratch, wire)
	if err != nil {
		t.Fatal(err)
	}
	if route.SessionID != sessionID {
		t.Fatalf("session id=%x, want %x", route.SessionID, sessionID)
	}
	plaintext, err := serverSession.AuthenticateInPlace(serverScratch, wire, route.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	inner, _, err := dataplane.ParseDataIPv4(plaintext, dataplane.ReferenceTunnelMTU)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inner, request) {
		t.Fatal("server received different inner packet")
	}

	reply := testIPv4Packet(serverIP, clientIP, 104)
	replyBuffer := make([]byte, 0, len(reply)+dataplane.MaxDataExpansion)
	replyWire, _, err := serverSession.SealDataTo(serverScratch, replyBuffer, reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outerServer.WriteToUDP(replyWire, clientOuter); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-device.writes:
		if !bytes.Equal(got, reply) {
			t.Fatal("device received different reply packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("device did not receive decrypted reply")
	}

	if err := runtime.requestClose(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close runtime: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("runtime returned error after close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not stop")
	}
}

func TestEmbeddedRuntimeTransportReplacementKeepsCurrentSession(t *testing.T) {
	clientIP := netip.MustParseAddr("10.66.0.2")
	serverIP := netip.MustParseAddr("10.66.0.1")
	outerServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer outerServer.Close()

	serverEndpoint := outerServer.LocalAddr().(*net.UDPAddr).AddrPort()
	transport1, err := net.DialUDP("udp4", nil, outerServer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	var routeKey, c2s, s2c [32]byte
	for i := 0; i < 32; i++ {
		routeKey[i] = byte(i + 1)
		c2s[i] = byte(0x41 + i)
		s2c[i] = byte(0x81 + i)
	}

	const sessionID uint64 = 0x4bb4dc219f112817
	clientSession, err := dataplane.NewSession(sessionID, c2s, s2c, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverSession, err := dataplane.NewSession(sessionID, s2c, c2s, 0)
	if err != nil {
		t.Fatal(err)
	}
	core, err := coreclient.New(coreclient.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: coreclient.LifecycleConfig{
			GenerationLifetime: 24 * time.Hour,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientSession,
	})
	if err != nil {
		t.Fatal(err)
	}

	device := newTestPacketDevice()
	runtime, err := newEmbeddedRuntime(device, transport1, core, serverEndpoint, dataplane.ReferenceTunnelMTU)
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run() }()
	select {
	case <-runtime.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not become ready")
	}

	readDATA := func(want []byte) netip.AddrPort {
		t.Helper()
		if err := outerServer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, 2048)
		n, source, err := outerServer.ReadFromUDP(wire)
		if err != nil {
			t.Fatal(err)
		}
		wire = wire[:n]
		scratch, err := dataplane.NewDataScratch(routeKey)
		if err != nil {
			t.Fatal(err)
		}
		route, err := dataplane.DecodeRoute(scratch, wire)
		if err != nil {
			t.Fatal(err)
		}
		if route.SessionID != sessionID {
			t.Fatalf("session id=%x, want %x", route.SessionID, sessionID)
		}
		plaintext, err := serverSession.AuthenticateInPlace(scratch, wire, route.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		inner, _, err := dataplane.ParseDataIPv4(plaintext, dataplane.ReferenceTunnelMTU)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(inner, want) {
			t.Fatal("server received different inner packet")
		}
		return source.AddrPort()
	}

	first := testIPv4Packet(clientIP, serverIP, 96)
	device.inject(first)
	firstSource := readDATA(first)

	transport2, err := net.DialUDP("udp4", nil, outerServer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.replaceTransport(transport2); err != nil {
		t.Fatal(err)
	}

	// Closing the previous generation wakes its RX loop. That stale close/error
	// must not terminate the runtime after generation 2 has been published.
	select {
	case err := <-runDone:
		t.Fatalf("runtime stopped after stale transport close: %v", err)
	case failure := <-runtime.transportFailures:
		t.Fatalf("stale transport close reported current failure: %+v", failure)
	case <-time.After(50 * time.Millisecond):
	}

	second := testIPv4Packet(clientIP, serverIP, 100)
	device.inject(second)
	secondSource := readDATA(second)
	if secondSource == firstSource {
		t.Fatalf("replacement kept the same outer source %v", secondSource)
	}

	if err := runtime.requestClose(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close runtime: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("runtime returned after close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not stop")
	}
}

type testPacketDevice struct {
	reads    chan []byte
	writes   chan []byte
	done     chan struct{}
	once     sync.Once
	closeErr error
}

func newTestPacketDevice() *testPacketDevice {
	return &testPacketDevice{
		reads:  make(chan []byte, 4),
		writes: make(chan []byte, 4),
		done:   make(chan struct{}),
	}
}

func (d *testPacketDevice) inject(packet []byte) {
	copyPacket := append([]byte(nil), packet...)
	d.reads <- copyPacket
}

func (d *testPacketDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-d.done:
		return 0, net.ErrClosed
	case packet := <-d.reads:
		if len(bufs) == 0 || len(sizes) == 0 || offset+len(packet) > len(bufs[0]) {
			return 0, errors.New("invalid test read buffer")
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	}
}

func (d *testPacketDevice) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-d.done:
		return 0, net.ErrClosed
	default:
	}
	for _, buffer := range bufs {
		if offset > len(buffer) {
			return 0, errors.New("invalid test write offset")
		}
		d.writes <- append([]byte(nil), buffer[offset:]...)
	}
	return len(bufs), nil
}

func (d *testPacketDevice) Close() error {
	d.once.Do(func() { close(d.done) })
	return d.closeErr
}

type shortWritePacketDevice struct {
	*testPacketDevice
}

func (d *shortWritePacketDevice) Write(_ [][]byte, _ int) (int, error) {
	return 0, nil
}

func TestEmbeddedRuntimeStartsWithoutInitialTransport(t *testing.T) {
	clientIP := netip.MustParseAddr("10.66.0.2")
	serverEndpoint := netip.MustParseAddrPort("192.0.2.1:51820")
	var routeKey, c2s, s2c [32]byte
	for i := range routeKey {
		routeKey[i] = byte(i + 1)
		c2s[i] = byte(0x41 + i)
		s2c[i] = byte(0x81 + i)
	}
	clientSession, err := dataplane.NewSession(0x10, c2s, s2c, 0)
	if err != nil {
		t.Fatal(err)
	}
	core, err := coreclient.New(coreclient.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: DefaultMTU,
		Lifecycle: coreclient.LifecycleConfig{
			GenerationLifetime: 24 * time.Hour,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientSession,
	})
	if err != nil {
		t.Fatal(err)
	}

	device := newTestPacketDevice()
	runtime, err := newEmbeddedRuntime(device, nil, core, serverEndpoint, DefaultMTU)
	if err != nil {
		t.Fatalf("newEmbeddedRuntime without transport: %v", err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run() }()
	select {
	case <-runtime.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not start without transport")
	}
	select {
	case err := <-runDone:
		t.Fatalf("runtime stopped while disconnected: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	transport, peer := net.Pipe()
	defer peer.Close()
	if _, err := runtime.replaceTransport(transport); err != nil {
		t.Fatalf("replace disconnected transport: %v", err)
	}
	runtime.transportMu.Lock()
	current := runtime.transport
	runtime.transportMu.Unlock()
	if current == nil || current.id != 1 {
		t.Fatalf("first published generation=%v, want generation 1", current)
	}

	if err := runtime.requestClose(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close runtime: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("runtime returned after close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not stop")
	}
}

func TestEmbeddedRuntimeExternalCurrentTransportCloseIsRecoverable(t *testing.T) {
	clientIP := netip.MustParseAddr("10.66.0.2")
	serverEndpoint := netip.MustParseAddrPort("192.0.2.1:51820")
	var routeKey, c2s, s2c [32]byte
	for i := range routeKey {
		routeKey[i] = byte(i + 1)
		c2s[i] = byte(0x41 + i)
		s2c[i] = byte(0x81 + i)
	}
	clientSession, err := dataplane.NewSession(0x12, c2s, s2c, 0)
	if err != nil {
		t.Fatal(err)
	}
	core, err := coreclient.New(coreclient.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: DefaultMTU,
		Lifecycle: coreclient.LifecycleConfig{
			GenerationLifetime: 24 * time.Hour,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientSession,
	})
	if err != nil {
		t.Fatal(err)
	}

	transport, peer := net.Pipe()
	defer peer.Close()
	device := newTestPacketDevice()
	runtime, err := newEmbeddedRuntime(device, transport, core, serverEndpoint, DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run() }()
	select {
	case <-runtime.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not become ready")
	}

	// sing-box NetworkManager.ResetNetwork closes tracked connections before it
	// invokes InterfaceUpdated. Simulate that ownership edge by externally
	// closing the current socket while the Opaque runtime is still alive.
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case failure := <-runtime.transportFailures:
		if failure.Generation != 1 {
			t.Fatalf("failure generation=%d, want 1", failure.Generation)
		}
		if failure.Err == nil {
			t.Fatal("transport close did not preserve read failure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("external transport close was not reported")
	}
	select {
	case err := <-runDone:
		t.Fatalf("runtime stopped on recoverable transport close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	runtime.transportMu.Lock()
	current := runtime.transport
	runtime.transportMu.Unlock()
	if current != nil {
		t.Fatal("externally closed transport remained current")
	}

	if err := runtime.requestClose(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close runtime: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("runtime returned after close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not stop")
	}
}

func TestEmbeddedRuntimeWriteFailureInvalidatesCurrentTransport(t *testing.T) {
	clientIP := netip.MustParseAddr("10.66.0.2")
	serverEndpoint := netip.MustParseAddrPort("192.0.2.1:51820")
	var routeKey, c2s, s2c [32]byte
	for i := range routeKey {
		routeKey[i] = byte(i + 1)
		c2s[i] = byte(0x41 + i)
		s2c[i] = byte(0x81 + i)
	}
	clientSession, err := dataplane.NewSession(0x11, c2s, s2c, 0)
	if err != nil {
		t.Fatal(err)
	}
	core, err := coreclient.New(coreclient.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: DefaultMTU,
		Lifecycle: coreclient.LifecycleConfig{
			GenerationLifetime: 24 * time.Hour,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientSession,
	})
	if err != nil {
		t.Fatal(err)
	}

	transport, peer := net.Pipe()
	device := newTestPacketDevice()
	runtime, err := newEmbeddedRuntime(device, transport, core, serverEndpoint, DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}

	if err := runtime.writer.WriteDatagram([]byte{1}, serverEndpoint); err != nil {
		t.Fatalf("recoverable write failure escaped writer: %v", err)
	}
	select {
	case failure := <-runtime.transportFailures:
		if failure.Generation != 1 {
			t.Fatalf("failure generation=%d, want 1", failure.Generation)
		}
		if failure.Err == nil {
			t.Fatal("transport failure did not preserve cause")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transport write failure was not reported")
	}

	runtime.transportMu.Lock()
	current := runtime.transport
	runtime.transportMu.Unlock()
	if current != nil {
		t.Fatal("failed transport remained current")
	}
	if err := runtime.disposeUnstarted(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dispose runtime: %v", err)
	}
}

func TestEmbeddedRuntimeReplacementDoesNotWaitForBlockedWrite(t *testing.T) {
	clientIP := netip.MustParseAddr("10.66.0.2")
	serverEndpoint := netip.MustParseAddrPort("192.0.2.1:51820")
	var routeKey, c2s, s2c [32]byte
	for i := range routeKey {
		routeKey[i] = byte(i + 1)
		c2s[i] = byte(0x41 + i)
		s2c[i] = byte(0x81 + i)
	}
	clientSession, err := dataplane.NewSession(0x14, c2s, s2c, 0)
	if err != nil {
		t.Fatal(err)
	}
	core, err := coreclient.New(coreclient.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: DefaultMTU,
		Lifecycle: coreclient.LifecycleConfig{
			GenerationLifetime: 24 * time.Hour,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientSession,
	})
	if err != nil {
		t.Fatal(err)
	}

	blockedBase, blockedPeer := net.Pipe()
	defer blockedPeer.Close()
	blocked := &blockingWriteConn{
		Conn:    blockedBase,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	runtime, err := newEmbeddedRuntime(newTestPacketDevice(), blocked, core, serverEndpoint, DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}

	writeDone := make(chan error, 1)
	go func() { writeDone <- runtime.writer.WriteDatagram([]byte{1}, serverEndpoint) }()
	select {
	case <-blocked.started:
	case <-time.After(2 * time.Second):
		t.Fatal("old transport write did not block")
	}

	replacement, replacementPeer := net.Pipe()
	defer replacementPeer.Close()
	replaceDone := make(chan error, 1)
	go func() {
		_, err := runtime.replaceTransport(replacement)
		replaceDone <- err
	}()
	select {
	case err := <-replaceDone:
		if err != nil {
			t.Fatalf("replace transport: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("replacement waited for an in-flight write on the old transport")
	}

	close(blocked.release)
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("stale write returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("old transport write did not finish")
	}

	runtime.transportMu.Lock()
	current := runtime.transport
	runtime.transportMu.Unlock()
	if current == nil || current.conn != replacement {
		t.Fatal("stale write invalidated replacement transport")
	}

	if err := runtime.disposeUnstarted(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dispose runtime: %v", err)
	}
}

func TestEmbeddedRuntimeEMSGSIZEDoesNotInvalidateTransport(t *testing.T) {
	clientIP := netip.MustParseAddr("10.66.0.2")
	serverEndpoint := netip.MustParseAddrPort("192.0.2.1:51820")
	var routeKey, c2s, s2c [32]byte
	for i := range routeKey {
		routeKey[i] = byte(i + 1)
		c2s[i] = byte(0x41 + i)
		s2c[i] = byte(0x81 + i)
	}
	clientSession, err := dataplane.NewSession(0x13, c2s, s2c, 0)
	if err != nil {
		t.Fatal(err)
	}
	core, err := coreclient.New(coreclient.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: DefaultMTU,
		Lifecycle: coreclient.LifecycleConfig{
			GenerationLifetime: 24 * time.Hour,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientSession,
	})
	if err != nil {
		t.Fatal(err)
	}

	base, peer := net.Pipe()
	defer peer.Close()
	transport := &writeErrorConn{Conn: base, err: syscall.EMSGSIZE}
	runtime, err := newEmbeddedRuntime(newTestPacketDevice(), transport, core, serverEndpoint, DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.writer.WriteDatagram([]byte{1}, serverEndpoint); err != nil {
		t.Fatalf("EMSGSIZE escaped writer: %v", err)
	}
	runtime.transportMu.Lock()
	current := runtime.transport
	runtime.transportMu.Unlock()
	if current == nil {
		t.Fatal("EMSGSIZE invalidated current transport")
	}
	select {
	case failure := <-runtime.transportFailures:
		t.Fatalf("EMSGSIZE emitted transport failure: %+v", failure)
	default:
	}
	if err := runtime.disposeUnstarted(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dispose runtime: %v", err)
	}
}

func TestEmbeddedRuntimeRejectsShortPacketDeviceWrite(t *testing.T) {
	device := &shortWritePacketDevice{testPacketDevice: newTestPacketDevice()}
	runtime := &embeddedRuntime{
		device:        device,
		rxDeviceWrite: make([][]byte, 0, 1),
	}

	buffer := make([]byte, dataplane.RouteSize+20)
	inner := buffer[dataplane.RouteSize:]
	inner[0] = 0x45
	err := runtime.consumeRXResults([]coreclient.RXResult{{
		Inbound: dataplane.InboundPacket{
			Kind: dataplane.InboundIPv4,
			IPv4: inner,
		},
		Buffer: buffer,
	}})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("consumeRXResults error=%v, want %v", err, io.ErrShortWrite)
	}
}

func testIPv4Packet(source, destination netip.Addr, totalLength int) []byte {
	if totalLength < 20 || totalLength > 0xffff {
		panic("invalid IPv4 test length")
	}
	packet := make([]byte, totalLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	packet[8] = 64
	packet[9] = 17
	source4 := source.As4()
	destination4 := destination.As4()
	copy(packet[12:16], source4[:])
	copy(packet[16:20], destination4[:])
	for i := 20; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	return packet
}

func TestNewClientRejectsOversizedMTU(t *testing.T) {
	device := newTestPacketDevice()
	transport, peer := net.Pipe()
	defer transport.Close()
	defer peer.Close()

	_, err := NewClient(testPublicClientConfig(t, MaxTunnelMTU+1), device, transport)
	if !errors.Is(err, dataplane.ErrInvalidConfig) {
		t.Fatalf("NewClient error=%v, want %v", err, dataplane.ErrInvalidConfig)
	}
}

func TestClientCloseBeforeRunReturnsOwnedCloseErrors(t *testing.T) {
	deviceErr := errors.New("device close failed")
	transportErr := errors.New("transport close failed")

	device := newTestPacketDevice()
	device.closeErr = deviceErr
	transportBase, peer := net.Pipe()
	defer peer.Close()
	transport := &closeErrorConn{Conn: transportBase, closeErr: transportErr}

	client, err := NewClient(testPublicClientConfig(t, DefaultMTU), device, transport)
	if err != nil {
		t.Fatal(err)
	}

	err = client.Close()
	if !errors.Is(err, deviceErr) {
		t.Fatalf("Close error=%v, want device error", err)
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("Close error=%v, want transport error", err)
	}
}

func TestClientRunNoiseEstablishmentAndDataRoundTrip(t *testing.T) {
	clientIP := netip.MustParseAddr("10.66.0.2")
	serverIP := netip.MustParseAddr("10.66.0.1")

	outerServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer outerServer.Close()

	serverEndpoint := outerServer.LocalAddr().(*net.UDPAddr).AddrPort()
	transport, err := net.DialUDP("udp4", nil, outerServer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0x30 + i)
	}
	clientPrivate := testNoisePrivateKey(1)
	serverPrivate := testNoisePrivateKey(33)
	clientPublic, err := noisehandshake.PublicKeyFromPrivate(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := noisehandshake.PublicKeyFromPrivate(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}

	serverCore, err := coreserver.New(coreserver.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: DefaultMTU,
		Lifecycle: coreserver.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: []coreserver.PeerConfig{{TunnelIPv4: clientIP}},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverHS, err := noisehandshake.NewServer(noisehandshake.ServerConfig{
		Core:             serverCore,
		StaticPrivateKey: serverPrivate,
		Peers: []noisehandshake.AuthorizedPeer{{
			TunnelIPv4: clientIP,
			PublicKey:  clientPublic,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	serverData := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		scratch, err := serverCore.NewDataScratch()
		if err != nil {
			serverErr <- err
			return
		}
		buffer := make([]byte, MaxTunnelMTU+dataplane.MaxDataExpansion)
		for {
			n, source, err := outerServer.ReadFromUDP(buffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case serverErr <- err:
				default:
				}
				return
			}
			packet := buffer[:n]
			route, routeErr := dataplane.DecodeRoute(scratch, packet)
			handled, response, destination, err := serverHS.TryHandleEstablishmentDatagramInPlace(
				source.AddrPort(),
				route,
				routeErr == nil,
				packet,
			)
			if err != nil {
				serverErr <- err
				return
			}
			if handled {
				if len(response) > 0 {
					if _, err := outerServer.WriteToUDP(response, net.UDPAddrFromAddrPort(destination)); err != nil {
						serverErr <- err
						return
					}
				}
				continue
			}
			if routeErr != nil {
				continue
			}

			inbound, response, destination, err := serverCore.HandleNetworkDatagramInPlace(
				scratch,
				source.AddrPort(),
				packet,
			)
			if err != nil {
				serverErr <- err
				return
			}
			if inbound.Kind == dataplane.InboundIPv4 {
				serverData <- append([]byte(nil), inbound.IPv4...)
			}
			if len(response) > 0 {
				if _, err := outerServer.WriteToUDP(response, net.UDPAddrFromAddrPort(destination)); err != nil {
					serverErr <- err
					return
				}
			}
		}
	}()

	device := newTestPacketDevice()
	client, err := NewClient(ClientConfig{
		TunnelIPv4:       clientIP,
		ServerEndpoint:   serverEndpoint,
		MTU:              DefaultMTU,
		RouteKey:         routeKey,
		StaticPrivateKey: [32]byte(clientPrivate),
		ServerPublicKey:  [32]byte(serverPublic),
	}, device, transport)
	if err != nil {
		t.Fatal(err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- client.Run(context.Background()) }()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer readyCancel()
	if err := client.WaitReady(readyCtx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}

	request := testIPv4Packet(clientIP, serverIP, 128)
	device.inject(request)
	select {
	case got := <-serverData:
		if !bytes.Equal(got, request) {
			t.Fatal("server received different client DATA packet")
		}
	case err := <-serverErr:
		t.Fatalf("server data loop: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive client DATA packet")
	}

	reply := testIPv4Packet(serverIP, clientIP, 132)
	serverTX, err := serverCore.NewDataScratch()
	if err != nil {
		t.Fatal(err)
	}
	wire, destination, err := serverCore.HandleInnerPacketTo(
		serverTX,
		make([]byte, 0, len(reply)+dataplane.MaxDataExpansion),
		reply,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outerServer.WriteToUDP(wire, net.UDPAddrFromAddrPort(destination)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-device.writes:
		if !bytes.Equal(got, reply) {
			t.Fatal("client device received different server DATA packet")
		}
	case err := <-serverErr:
		t.Fatalf("server reverse data loop: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("client device did not receive server DATA packet")
	}

	if err := client.Close(); err != nil {
		t.Fatalf("client.Close: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Client.Run returned after Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Client.Run did not stop after Close")
	}

	if err := outerServer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server loop did not stop")
	}
}

func TestClientReplaceTransportDuringEstablishment(t *testing.T) {
	clientIP := netip.MustParseAddr("10.66.0.2")
	outerServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer outerServer.Close()

	serverEndpoint := outerServer.LocalAddr().(*net.UDPAddr).AddrPort()
	transport1, err := net.DialUDP("udp4", nil, outerServer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0x30 + i)
	}
	clientPrivate := testNoisePrivateKey(1)
	serverPrivate := testNoisePrivateKey(33)
	clientPublic, err := noisehandshake.PublicKeyFromPrivate(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := noisehandshake.PublicKeyFromPrivate(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}

	serverCore, err := coreserver.New(coreserver.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: DefaultMTU,
		Lifecycle: coreserver.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: []coreserver.PeerConfig{{TunnelIPv4: clientIP}},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverHS, err := noisehandshake.NewServer(noisehandshake.ServerConfig{
		Core:             serverCore,
		StaticPrivateKey: serverPrivate,
		Peers: []noisehandshake.AuthorizedPeer{{
			TunnelIPv4: clientIP,
			PublicKey:  clientPublic,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	attemptSource := make(chan netip.AddrPort, 4)
	serverErr := make(chan error, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		scratch, err := serverCore.NewDataScratch()
		if err != nil {
			serverErr <- err
			return
		}
		buffer := make([]byte, MaxTunnelMTU+dataplane.MaxDataExpansion)
		responses := 0
		for {
			n, source, err := outerServer.ReadFromUDP(buffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case serverErr <- err:
				default:
				}
				return
			}
			packet := buffer[:n]
			route, routeErr := dataplane.DecodeRoute(scratch, packet)
			handled, response, destination, err := serverHS.TryHandleEstablishmentDatagramInPlace(
				source.AddrPort(),
				route,
				routeErr == nil,
				packet,
			)
			if err != nil {
				serverErr <- err
				return
			}
			if !handled {
				continue
			}
			if len(response) == 0 {
				continue
			}

			responses++
			attemptSource <- source.AddrPort()
			if responses == 1 {
				// Deliberately lose the first RESPONSE so establishment remains
				// active when the outer transport is replaced.
				continue
			}
			if _, err := outerServer.WriteToUDP(response, net.UDPAddrFromAddrPort(destination)); err != nil {
				serverErr <- err
				return
			}
		}
	}()

	device := newTestPacketDevice()
	client, err := NewClient(ClientConfig{
		TunnelIPv4:       clientIP,
		ServerEndpoint:   serverEndpoint,
		MTU:              DefaultMTU,
		RouteKey:         routeKey,
		StaticPrivateKey: [32]byte(clientPrivate),
		ServerPublicKey:  [32]byte(serverPublic),
	}, device, transport1)
	if err != nil {
		t.Fatal(err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- client.Run(context.Background()) }()

	var firstSource netip.AddrPort
	select {
	case firstSource = <-attemptSource:
	case err := <-serverErr:
		t.Fatalf("server establishment: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive initial establishment")
	}

	transport2, err := net.DialUDP("udp4", nil, outerServer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	generation, err := client.ReplaceTransport(transport2)
	if err != nil {
		t.Fatalf("ReplaceTransport: %v", err)
	}
	if generation != 2 {
		t.Fatalf("replacement generation=%d, want 2", generation)
	}

	var secondSource netip.AddrPort
	select {
	case secondSource = <-attemptSource:
	case err := <-serverErr:
		t.Fatalf("server establishment after replacement: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("transport replacement did not trigger immediate establishment retry")
	}
	if secondSource == firstSource {
		t.Fatalf("replacement establishment used old outer source %v", secondSource)
	}

	readyCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.WaitReady(readyCtx); err != nil {
		t.Fatalf("WaitReady after replacement: %v", err)
	}

	select {
	case err := <-runDone:
		t.Fatalf("Client.Run stopped after transport replacement: %v", err)
	default:
	}

	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("client.Close: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Client.Run returned after Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Client.Run did not stop after Close")
	}

	if err := outerServer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server loop did not stop")
	}
}

type blockingWriteConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingWriteConn) Write(packet []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return len(packet), nil
}

type writeErrorConn struct {
	net.Conn
	err error
}

func (c *writeErrorConn) Write([]byte) (int, error) {
	return 0, c.err
}

type closeErrorConn struct {
	net.Conn
	closeErr error
}

func (c *closeErrorConn) Close() error {
	_ = c.Conn.Close()
	return c.closeErr
}

func testPublicClientConfig(t *testing.T, mtu int) ClientConfig {
	t.Helper()
	clientPrivate := testNoisePrivateKey(1)
	serverPrivate := testNoisePrivateKey(33)
	serverPublic, err := noisehandshake.PublicKeyFromPrivate(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return ClientConfig{
		TunnelIPv4:       netip.MustParseAddr("10.66.0.2"),
		ServerEndpoint:   netip.MustParseAddrPort("192.0.2.1:51820"),
		MTU:              mtu,
		RouteKey:         [32]byte{1},
		StaticPrivateKey: [32]byte(clientPrivate),
		ServerPublicKey:  [32]byte(serverPublic),
	}
}

func testNoisePrivateKey(start byte) noisehandshake.PrivateKey {
	var key noisehandshake.PrivateKey
	for i := range key {
		key[i] = start + byte(i)
	}
	return key
}
