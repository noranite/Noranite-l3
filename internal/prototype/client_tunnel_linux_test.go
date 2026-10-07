//go:build linux

package prototype

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/establishment"
	"github.com/noranite/Noranite-l3/internal/server"
	"github.com/noranite/Noranite-l3/internal/tun"
)

type clientRuntimeTestTun struct {
	mu     sync.Mutex
	writes [][]byte

	events chan tun.Event
	reads  chan []byte
	closed chan struct{}
	wrote  chan struct{}
	once   sync.Once
}

func newClientRuntimeTestTun() *clientRuntimeTestTun {
	return &clientRuntimeTestTun{
		events: make(chan tun.Event),
		reads:  make(chan []byte, 8),
		closed: make(chan struct{}),
		wrote:  make(chan struct{}, 8),
	}
}

func (d *clientRuntimeTestTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-d.closed:
		return 0, os.ErrClosed
	case packet := <-d.reads:
		if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset+len(packet) > len(bufs[0]) {
			return 0, errors.New("invalid test TUN read buffer")
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	}
}

func (d *clientRuntimeTestTun) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-d.closed:
		return 0, os.ErrClosed
	default:
	}

	d.mu.Lock()
	for _, buffer := range bufs {
		if offset < 0 || offset > len(buffer) {
			d.mu.Unlock()
			return 0, errors.New("invalid test TUN offset")
		}
		d.writes = append(d.writes, bytes.Clone(buffer[offset:]))
	}
	d.mu.Unlock()

	select {
	case d.wrote <- struct{}{}:
	default:
	}
	return len(bufs), nil
}

func (d *clientRuntimeTestTun) MTU() (int, error)        { return dataplane.ReferenceTunnelMTU, nil }
func (d *clientRuntimeTestTun) Name() (string, error)    { return "client-test", nil }
func (d *clientRuntimeTestTun) BatchSize() int           { return 4 }
func (d *clientRuntimeTestTun) Events() <-chan tun.Event { return d.events }
func (d *clientRuntimeTestTun) Close() error {
	d.once.Do(func() {
		close(d.closed)
		close(d.events)
	})
	return nil
}

func (d *clientRuntimeTestTun) Inject(packet []byte) {
	d.reads <- bytes.Clone(packet)
}

func (d *clientRuntimeTestTun) WaitWrite(t *testing.T) {
	t.Helper()
	select {
	case <-d.wrote:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for test TUN write")
	}
}

func (d *clientRuntimeTestTun) Writes() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.writes))
	for i := range d.writes {
		out[i] = bytes.Clone(d.writes[i])
	}
	return out
}

func TestNewClientRuntimeRejectsEngineBatchSmallerThanTun(t *testing.T) {
	clientSession, _ := clientRuntimeSessionPair(t, 0xa101, 0x11)
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(i + 1)
	}
	core, err := client.New(client.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         netip.MustParseAddr("10.88.0.2"),
		ServerEndpoint:     netip.MustParseAddrPort("127.0.0.1:51820"),
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: client.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientSession,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	tests := []struct {
		name   string
		config ClientRuntimeConfig
	}{
		{
			name: "TX",
			config: ClientRuntimeConfig{
				TXEngine: client.TXEngineConfig{BatchSize: 2},
			},
		},
		{
			name: "RX",
			config: ClientRuntimeConfig{
				RXEngine: client.RXEngineConfig{BatchSize: 2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClientRuntime(
				newClientRuntimeTestTun(),
				conn,
				core,
				dataplane.ReferenceTunnelMTU,
				tt.config,
			)
			if !errors.Is(err, dataplane.ErrInvalidConfig) {
				t.Fatalf("NewClientRuntime error=%v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestRunClientTunnelRoundTripAndShutdown(t *testing.T) {
	var routeKey, c2s, s2c [32]byte
	for i := 0; i < 32; i++ {
		routeKey[i] = byte(i + 1)
		c2s[i] = byte(0x40 + i)
		s2c[i] = byte(0x80 + i)
	}

	const sessionID uint64 = 0xa530
	clientSession, err := dataplane.NewSession(sessionID, c2s, s2c, 0)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}
	serverSession, err := dataplane.NewSession(sessionID, s2c, c2s, 0)
	if err != nil {
		t.Fatalf("NewSession(server): %v", err)
	}

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}

	serverEndpoint := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	clientIP := netip.MustParseAddr("10.66.0.2")
	serverIP := netip.MustParseAddr("10.66.0.1")
	core, err := client.New(client.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: client.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientSession,
	})
	if err != nil {
		_ = clientConn.Close()
		t.Fatalf("client.New: %v", err)
	}

	dev := newClientRuntimeTestTun()
	runtimeDone := make(chan error, 1)
	go func() {
		runtimeDone <- RunClientTunnel(dev, clientConn, core, dataplane.ReferenceTunnelMTU)
	}()

	toServer := clientRuntimeIPv4Packet(t, clientIP, serverIP, []byte("full runtime tx"))
	dev.Inject(toServer)

	serverWire := make([]byte, dataplane.ReferenceTunnelMTU+dataplane.MaxDataExpansion)
	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(server): %v", err)
	}
	n, source, err := serverConn.ReadFromUDPAddrPort(serverWire)
	if err != nil {
		t.Fatalf("ReadFromUDPAddrPort(server): %v", err)
	}
	serverWire = serverWire[:n]

	serverScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("NewDataScratch(server): %v", err)
	}
	route, err := dataplane.DecodeRoute(serverScratch, serverWire)
	if err != nil {
		t.Fatalf("DecodeRoute(client TX): %v", err)
	}
	plaintext, err := serverSession.AuthenticateInPlace(serverScratch, serverWire, route.Sequence)
	if err != nil {
		t.Fatalf("AuthenticateInPlace(client TX): %v", err)
	}
	opened, _, err := dataplane.ParseDataIPv4(plaintext, dataplane.ReferenceTunnelMTU)
	if err != nil {
		t.Fatalf("ParseDataIPv4(client TX): %v", err)
	}
	if !bytes.Equal(opened, toServer) {
		t.Fatal("client runtime TX plaintext differs from injected TUN packet")
	}

	toClient := clientRuntimeIPv4Packet(t, serverIP, clientIP, []byte("full runtime rx"))
	wireToClient, _, err := serverSession.SealDataTo(
		serverScratch,
		make([]byte, 0, len(toClient)+dataplane.MaxDataExpansion),
		toClient,
	)
	if err != nil {
		t.Fatalf("SealDataTo(server): %v", err)
	}
	if _, err := serverConn.WriteToUDPAddrPort(wireToClient, source); err != nil {
		t.Fatalf("WriteToUDPAddrPort(server): %v", err)
	}

	dev.WaitWrite(t)
	writes := dev.Writes()
	if len(writes) != 1 || !bytes.Equal(writes[0], toClient) {
		t.Fatalf("runtime TUN writes=%q, want one packet %q", writes, toClient)
	}

	// Make the TUN reader return os.ErrClosed. RunClientTunnel must use that
	// terminal ingress error to close UDP, drain accepted work and return.
	_ = dev.Close()
	select {
	case runtimeErr := <-runtimeDone:
		if !errors.Is(runtimeErr, os.ErrClosed) {
			t.Fatalf("RunClientTunnel error=%v, want os.ErrClosed", runtimeErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunClientTunnel did not finish after terminal TUN error")
	}
}

func clientRuntimeIPv4Packet(
	t *testing.T,
	source netip.Addr,
	destination netip.Addr,
	payload []byte,
) []byte {
	t.Helper()
	if !source.Is4() || !destination.Is4() {
		t.Fatalf("runtime test addresses must be IPv4: %v -> %v", source, destination)
	}

	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	src := source.As4()
	dst := destination.As4()
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	copy(packet[20:], payload)
	return packet
}

func TestClientRuntimeSameSocketLiveRotationUsesNextDATA(t *testing.T) {
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(i + 1)
	}

	clientA, serverA := clientRuntimeSessionPair(t, 0xb100, 0x10)
	clientB, serverB := clientRuntimeSessionPair(t, 0xb101, 0x30)
	clientIP := netip.MustParseAddr("10.77.0.2")
	serverIP := netip.MustParseAddr("10.77.0.1")

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}

	serverEndpoint := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	lifecycle := client.LifecycleConfig{
		GenerationLifetime: 30 * time.Second,
		ReceiveGrace:       5 * time.Second,
	}
	clientCore, err := client.New(client.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          lifecycle,
		Session:            clientA,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	serverCore, err := server.New(server.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: lifecycle.GenerationLifetime,
			ReceiveGrace:       lifecycle.ReceiveGrace,
		},
		Peers: []server.PeerConfig{{
			TunnelIPv4:     clientIP,
			InitialSession: serverA,
		}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	dev := newClientRuntimeTestTun()
	runtime, err := NewClientRuntime(
		dev,
		clientConn,
		clientCore,
		dataplane.ReferenceTunnelMTU,
		ClientRuntimeConfig{},
	)
	if err != nil {
		t.Fatalf("NewClientRuntime: %v", err)
	}

	clientHello := []byte("test-client-rekey-request")
	serverResponse := []byte("test-server-session-b")
	installed := make(chan struct{})
	var installOnce sync.Once
	if err := runtime.SetDatagramDemux(ClientDatagramDemuxFunc(func(
		source netip.AddrPort,
		_ dataplane.Route,
		_ bool,
		packet []byte,
	) (bool, error) {
		if !bytes.Equal(packet, serverResponse) {
			return false, nil
		}
		if source != serverEndpoint {
			return true, errors.New("test rekey response came from unexpected endpoint")
		}
		if _, err := clientCore.InstallInitiatorSession(clientB); err != nil {
			return true, err
		}
		installOnce.Do(func() { close(installed) })
		return true, nil
	})); err != nil {
		t.Fatalf("SetDatagramDemux: %v", err)
	}

	runtimeDone := make(chan error, 1)
	go func() { runtimeDone <- runtime.Run() }()
	select {
	case <-runtime.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("client runtime did not become ready")
	}

	// Future handshake initiation can write through the same runtime-owned UDP
	// socket without competing with UDP receive ownership.
	if err := runtime.SendProtocolDatagram(clientHello, serverEndpoint); err != nil {
		t.Fatalf("SendProtocolDatagram: %v", err)
	}
	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(server): %v", err)
	}
	buf := make([]byte, 2048)
	n, clientEndpoint, err := serverConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("read synthetic rekey request: %v", err)
	}
	if !bytes.Equal(buf[:n], clientHello) {
		t.Fatalf("synthetic rekey request=%q, want %q", buf[:n], clientHello)
	}

	// The synthetic responder installs B as pending before returning the
	// handshake response. Client UDP ingress consumes that response through the
	// demux and installs B current while the tunnel is already live.
	if err := serverCore.InstallPendingSession(clientIP, serverB); err != nil {
		t.Fatalf("InstallPendingSession(B): %v", err)
	}
	if _, err := serverConn.WriteToUDPAddrPort(serverResponse, clientEndpoint); err != nil {
		t.Fatalf("write synthetic rekey response: %v", err)
	}
	select {
	case <-installed:
	case <-time.After(3 * time.Second):
		t.Fatal("client live rekey response was not consumed by demux")
	}

	// No activation CONTROL is needed when DATA is ready. The first TUN packet
	// after install must use B and therefore promote server pending B.
	toServer := clientRuntimeIPv4Packet(t, clientIP, serverIP, []byte("live rekey data B"))
	dev.Inject(toServer)
	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(server DATA): %v", err)
	}
	n, source, err := serverConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("read DATA(B): %v", err)
	}
	serverScratch, err := serverCore.NewDataScratch()
	if err != nil {
		t.Fatalf("server.NewDataScratch: %v", err)
	}
	opened, err := serverCore.HandleDatagramInPlace(serverScratch, source, buf[:n])
	if err != nil {
		t.Fatalf("server HandleDatagramInPlace(DATA B): %v", err)
	}
	if !bytes.Equal(opened, toServer) {
		t.Fatal("server plaintext after live rekey differs from TUN DATA")
	}
	if serverCore.CurrentSession(clientIP) != serverB {
		t.Fatal("server did not promote pending B on live DATA(B)")
	}

	// Reverse B must fall through the same demux into encrypted transport RX and
	// reach TUN. This proves the demux is not a second competing UDP reader.
	toClient := clientRuntimeIPv4Packet(t, serverIP, clientIP, []byte("reverse B after live rekey"))
	wireToClient, destination, err := serverCore.HandleInnerPacketTo(
		serverScratch,
		make([]byte, 0, len(toClient)+dataplane.MaxDataExpansion),
		toClient,
	)
	if err != nil {
		t.Fatalf("server HandleInnerPacketTo(B): %v", err)
	}
	if destination != source {
		t.Fatalf("reverse destination=%v, want learned client endpoint %v", destination, source)
	}
	if _, err := serverConn.WriteToUDPAddrPort(wireToClient, destination); err != nil {
		t.Fatalf("write reverse DATA(B): %v", err)
	}
	dev.WaitWrite(t)
	writes := dev.Writes()
	if len(writes) != 1 || !bytes.Equal(writes[0], toClient) {
		t.Fatalf("TUN writes=%q, want reverse B packet %q", writes, toClient)
	}

	_ = dev.Close()
	select {
	case runtimeErr := <-runtimeDone:
		if !errors.Is(runtimeErr, os.ErrClosed) {
			t.Fatalf("runtime error=%v, want os.ErrClosed", runtimeErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not stop after TUN close")
	}
}

func TestClientRuntimeIdleRotationUsesSharedTXEngineForActivation(t *testing.T) {
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0x80 + i)
	}

	clientA, serverA := clientRuntimeSessionPair(t, 0xb200, 0x50)
	clientB, serverB := clientRuntimeSessionPair(t, 0xb201, 0x70)
	clientIP := netip.MustParseAddr("10.78.0.2")

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}

	serverEndpoint := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	clientCore, err := client.New(client.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: client.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientA,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	serverCore, err := server.New(server.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: []server.PeerConfig{{TunnelIPv4: clientIP, InitialSession: serverA}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := serverCore.InstallPendingSession(clientIP, serverB); err != nil {
		t.Fatalf("InstallPendingSession(B): %v", err)
	}

	dev := newClientRuntimeTestTun()
	runtime, err := NewClientRuntime(
		dev,
		clientConn,
		clientCore,
		dataplane.ReferenceTunnelMTU,
		ClientRuntimeConfig{},
	)
	if err != nil {
		t.Fatalf("NewClientRuntime: %v", err)
	}

	serverResponse := []byte("test-idle-server-session-b")
	submitted := make(chan struct{})
	const keepaliveID uint64 = 0x0102030405060708
	if err := runtime.SetDatagramDemux(ClientDatagramDemuxFunc(func(
		source netip.AddrPort,
		_ dataplane.Route,
		_ bool,
		packet []byte,
	) (bool, error) {
		if !bytes.Equal(packet, serverResponse) {
			return false, nil
		}
		if source != serverEndpoint {
			return true, errors.New("test session response came from unexpected endpoint")
		}
		if _, err := clientCore.InstallInitiatorSession(clientB); err != nil {
			return true, err
		}
		op, err := clientCore.AdmitKeepalive(keepaliveID, dataplane.MaxGeneratedControlWirePacketSize)
		if err != nil {
			return true, err
		}
		if err := runtime.SubmitProtocolTransport(op); err != nil {
			return true, err
		}
		close(submitted)
		return true, nil
	})); err != nil {
		t.Fatalf("SetDatagramDemux: %v", err)
	}

	runtimeDone := make(chan error, 1)
	go func() { runtimeDone <- runtime.Run() }()
	select {
	case <-runtime.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("client runtime did not become ready")
	}

	clientEndpoint := clientConn.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, err := serverConn.WriteToUDPAddrPort(serverResponse, clientEndpoint); err != nil {
		t.Fatalf("write synthetic session response: %v", err)
	}
	select {
	case <-submitted:
	case <-time.After(3 * time.Second):
		t.Fatal("activation transport was not submitted")
	}

	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(server): %v", err)
	}
	wire := make([]byte, dataplane.MaxGeneratedControlWirePacketSize)
	n, source, err := serverConn.ReadFromUDPAddrPort(wire)
	if err != nil {
		t.Fatalf("read activation KEEPALIVE(B): %v", err)
	}
	serverScratch, err := serverCore.NewDataScratch()
	if err != nil {
		t.Fatalf("server.NewDataScratch: %v", err)
	}
	inbound, ack, ackDestination, err := serverCore.HandleNetworkDatagramInPlace(
		serverScratch,
		source,
		wire[:n],
	)
	if err != nil {
		t.Fatalf("HandleNetworkDatagramInPlace(KEEPALIVE B): %v", err)
	}
	if inbound.Kind != dataplane.InboundKeepalive || inbound.KeepaliveID != keepaliveID {
		t.Fatalf("activation inbound=%+v, want KEEPALIVE id %#x", inbound, keepaliveID)
	}
	if serverCore.CurrentSession(clientIP) != serverB {
		t.Fatal("server did not promote B from protocol-generated activation transport")
	}
	if len(ack) == 0 || ackDestination != source {
		t.Fatalf("activation ACK len=%d destination=%v, want response to %v", len(ack), ackDestination, source)
	}

	_ = dev.Close()
	select {
	case runtimeErr := <-runtimeDone:
		if !errors.Is(runtimeErr, os.ErrClosed) {
			t.Fatalf("runtime error=%v, want os.ErrClosed", runtimeErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not stop after TUN close")
	}
}

type clientRuntimeControllerFactory struct {
	serverEndpoint netip.AddrPort
	response       []byte
	material       establishment.TrafficSessionMaterial
}

func (f *clientRuntimeControllerFactory) IsEstablishmentDatagram(
	_ dataplane.Route,
	_ bool,
	packet []byte,
) bool {
	return bytes.Equal(packet, f.response)
}

func (f *clientRuntimeControllerFactory) Start(
	_ time.Time,
) (client.EstablishmentAttempt, client.EstablishmentUpdate, error) {
	return &clientRuntimeControllerAttempt{
		serverEndpoint: f.serverEndpoint,
		response:       bytes.Clone(f.response),
		material:       f.material,
	}, client.EstablishmentUpdate{Outbound: []client.EstablishmentDatagram{{
		Packet:      []byte("controller-rekey-b"),
		Destination: f.serverEndpoint,
	}}}, nil
}

type clientRuntimeControllerAttempt struct {
	serverEndpoint netip.AddrPort
	response       []byte
	material       establishment.TrafficSessionMaterial
}

func (a *clientRuntimeControllerAttempt) HandleDatagram(
	_ time.Time,
	source netip.AddrPort,
	_ dataplane.Route,
	_ bool,
	packet []byte,
) (bool, client.EstablishmentUpdate, error) {
	if !bytes.Equal(packet, a.response) {
		return false, client.EstablishmentUpdate{}, nil
	}
	if source != a.serverEndpoint {
		return true, client.EstablishmentUpdate{}, nil
	}
	material := a.material
	return true, client.EstablishmentUpdate{Material: &material}, nil
}

func (a *clientRuntimeControllerAttempt) Retry(
	_ time.Time,
) (client.EstablishmentUpdate, error) {
	return client.EstablishmentUpdate{Outbound: []client.EstablishmentDatagram{{
		Packet:      []byte("controller-rekey-b"),
		Destination: a.serverEndpoint,
	}}}, nil
}

func TestClientSessionControllerSameSocketLostActivationFallsBackToDATA(t *testing.T) {
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0x30 + i)
	}

	clientA, serverA := clientRuntimeSessionPair(t, 0xb300, 0x20)
	clientB, serverB := clientRuntimeSessionPair(t, 0xb301, 0x60)
	clientIP := netip.MustParseAddr("10.79.0.2")
	serverIP := netip.MustParseAddr("10.79.0.1")

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}

	serverEndpoint := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	lifecycle := client.LifecycleConfig{
		GenerationLifetime: 30 * time.Second,
		ReceiveGrace:       5 * time.Second,
	}
	clientCore, err := client.New(client.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          lifecycle,
		Session:            clientA,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	serverCore, err := server.New(server.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: lifecycle.GenerationLifetime,
			ReceiveGrace:       lifecycle.ReceiveGrace,
		},
		Peers: []server.PeerConfig{{TunnelIPv4: clientIP, InitialSession: serverA}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	dev := newClientRuntimeTestTun()
	runtime, err := NewClientRuntime(
		dev,
		clientConn,
		clientCore,
		dataplane.ReferenceTunnelMTU,
		ClientRuntimeConfig{},
	)
	if err != nil {
		t.Fatalf("NewClientRuntime: %v", err)
	}

	var c2s, s2c [32]byte
	for i := 0; i < 32; i++ {
		c2s[i] = 0x60 + byte(i)
		s2c[i] = 0xa0 + byte(i)
	}
	materialB := establishment.TrafficSessionMaterial{
		SessionID: clientB.ID(),
		C2S:       c2s,
		S2C:       s2c,
	}
	// clientRuntimeSessionPair used the same derivation for seed 0x60.
	// Keep this assertion local so the synthetic establishment material cannot
	// silently drift from the server pending Session used below.
	materialClientB, err := establishment.NewClientSession(materialB)
	if err != nil {
		t.Fatalf("NewClientSession(B material): %v", err)
	}
	if materialClientB.ID() != clientB.ID() {
		t.Fatal("synthetic B material session ID mismatch")
	}

	response := []byte("controller-session-b-established")
	controller, err := client.NewSessionController(
		clientCore,
		runtime,
		&clientRuntimeControllerFactory{
			serverEndpoint: serverEndpoint,
			response:       response,
			material:       materialB,
		},
		client.SessionControllerConfig{
			SoftRekeyAfter:        20 * time.Second,
			EstablishmentRetryMin: time.Second,
			EstablishmentRetryMax: time.Second,
		},
	)
	if err != nil {
		t.Fatalf("NewSessionController: %v", err)
	}
	if err := runtime.SetDatagramDemux(controller); err != nil {
		t.Fatalf("SetDatagramDemux(controller): %v", err)
	}

	runtimeDone := make(chan error, 1)
	go func() { runtimeDone <- runtime.Run() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(ctx) }()

	select {
	case <-runtime.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("client runtime did not become ready")
	}
	controller.RequestRekey()

	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(establishment): %v", err)
	}
	buf := make([]byte, 2048)
	n, clientEndpoint, err := serverConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("read controller establishment request: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("controller-rekey-b")) {
		t.Fatalf("controller request=%q", buf[:n])
	}

	if err := serverCore.InstallPendingSession(clientIP, serverB); err != nil {
		t.Fatalf("InstallPendingSession(B): %v", err)
	}
	if _, err := serverConn.WriteToUDPAddrPort(response, clientEndpoint); err != nil {
		t.Fatalf("write controller establishment response: %v", err)
	}

	// Success must generate an unconditional activation transport before any DATA.
	// Deliberately drop it at the network boundary: lifecycle must not roll back
	// or wait for ACK/confirmation. The next DATA(B) remains sufficient to
	// promote server pending B.
	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(activation): %v", err)
	}
	n, _, err = serverConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("read controller activation: %v", err)
	}
	if n == 0 {
		t.Fatal("controller emitted empty activation datagram")
	}
	if serverCore.CurrentSession(clientIP) != serverA {
		t.Fatal("server changed generation even though activation was dropped")
	}

	// Ordinary application DATA is independent of activation and must use B.
	toServer := clientRuntimeIPv4Packet(t, clientIP, serverIP, []byte("data after controller activation"))
	dev.Inject(toServer)
	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(DATA): %v", err)
	}
	n, source, err := serverConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("read DATA(B): %v", err)
	}
	serverScratch, err := serverCore.NewDataScratch()
	if err != nil {
		t.Fatalf("server.NewDataScratch: %v", err)
	}
	opened, err := serverCore.HandleDatagramInPlace(serverScratch, source, buf[:n])
	if err != nil {
		t.Fatalf("server DATA(B) receive: %v", err)
	}
	if !bytes.Equal(opened, toServer) {
		t.Fatal("DATA after lost activation did not round-trip on B")
	}
	if serverCore.CurrentSession(clientIP) != serverB {
		t.Fatal("DATA(B) did not promote server after lost activation")
	}

	_ = dev.Close()
	select {
	case runtimeErr := <-runtimeDone:
		if !errors.Is(runtimeErr, os.ErrClosed) {
			t.Fatalf("runtime error=%v, want os.ErrClosed", runtimeErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not stop after TUN close")
	}
	select {
	case err := <-controllerDone:
		if err != nil {
			t.Fatalf("controller error after runtime shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("controller did not stop with runtime")
	}
}

func TestClientRuntimeSubmitProtocolTransportRacesShutdown(t *testing.T) {
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0x44 + i)
	}
	clientSession, _ := clientRuntimeSessionPair(t, 0xb380, 0x22)
	clientIP := netip.MustParseAddr("10.79.1.2")

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}

	core, err := client.New(client.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverConn.LocalAddr().(*net.UDPAddr).AddrPort(),
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: client.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Session: clientSession,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	dev := newClientRuntimeTestTun()
	runtime, err := NewClientRuntime(
		dev,
		clientConn,
		core,
		dataplane.ReferenceTunnelMTU,
		ClientRuntimeConfig{},
	)
	if err != nil {
		t.Fatalf("NewClientRuntime: %v", err)
	}

	runtimeDone := make(chan error, 1)
	go func() { runtimeDone <- runtime.Run() }()
	select {
	case <-runtime.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("client runtime did not become ready")
	}

	const submissions = 16
	ops := make([]*client.OutboundOperation, submissions)
	for i := range ops {
		op, err := core.AdmitKeepalive(uint64(0x9000+i), dataplane.MaxGeneratedControlWirePacketSize)
		if err != nil {
			t.Fatalf("AdmitKeepalive(%d): %v", i, err)
		}
		ops[i] = op
	}

	// Hold the exact close-boundary mutex so both shutdown and all submitters
	// queue behind the same barrier. Once released, each submission must either
	// transfer ownership to the TX engine while the boundary is open or observe
	// ErrClientRuntimeNotRunning after shutdown closes it.
	runtime.protocolMu.Lock()
	start := make(chan struct{})
	results := make(chan error, submissions)
	var submitWG sync.WaitGroup
	submitWG.Add(submissions)
	for _, op := range ops {
		op := op
		go func() {
			defer submitWG.Done()
			<-start
			results <- runtime.SubmitProtocolTransport(op)
		}()
	}
	close(start)

	shutdownErr := errors.New("test protocol submit/shutdown race")
	runtime.reporter.Report(shutdownErr)
	select {
	case <-dev.closed:
		// Run has observed the terminal error and entered shutdown. It cannot
		// cross the protocol producer boundary while this test holds protocolMu.
	case <-time.After(3 * time.Second):
		runtime.protocolMu.Unlock()
		t.Fatal("runtime did not enter shutdown")
	}
	runtime.protocolMu.Unlock()

	submitWG.Wait()
	close(results)
	accepted := 0
	rejected := 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrClientRuntimeNotRunning):
			rejected++
		default:
			t.Fatalf("SubmitProtocolTransport race returned unexpected error: %v", err)
		}
	}
	if accepted+rejected != submissions {
		t.Fatalf("submit results accepted=%d rejected=%d, want %d total", accepted, rejected, submissions)
	}

	select {
	case err := <-runtimeDone:
		if !errors.Is(err, shutdownErr) {
			t.Fatalf("runtime error=%v, want %v", err, shutdownErr)
		}
	case <-time.After(3 * time.Second):
		// Run cannot return until TXEngine.Close drains every accepted protocol
		// operation, so this also detects an ownership/drain deadlock at the close
		// boundary.
		t.Fatal("runtime shutdown did not drain accepted protocol submissions")
	}

	late, err := core.AdmitKeepalive(0xffff, dataplane.MaxGeneratedControlWirePacketSize)
	if err != nil {
		t.Fatalf("AdmitKeepalive(late): %v", err)
	}
	if err := runtime.SubmitProtocolTransport(late); !errors.Is(err, ErrClientRuntimeNotRunning) {
		t.Fatalf("late SubmitProtocolTransport err=%v, want ErrClientRuntimeNotRunning", err)
	}
}

func TestClientSessionControllerColdStartInstallsAndActivatesFirstGeneration(t *testing.T) {
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0x58 + i)
	}
	clientIP := netip.MustParseAddr("10.79.2.2")
	serverIP := netip.MustParseAddr("10.79.2.1")

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}

	serverEndpoint := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	lifecycle := client.LifecycleConfig{
		GenerationLifetime: 30 * time.Second,
		ReceiveGrace:       5 * time.Second,
	}
	clientCore, err := client.New(client.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          lifecycle,
		Session:            nil,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if clientCore.Session() != nil {
		t.Fatal("cold-start client unexpectedly has a current Session")
	}
	if _, err := clientCore.AdmitKeepalive(1, dataplane.MaxGeneratedControlWirePacketSize); !errors.Is(err, client.ErrNoCurrentSession) {
		t.Fatalf("AdmitKeepalive before establishment err=%v, want ErrNoCurrentSession", err)
	}

	serverCore, err := server.New(server.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: lifecycle.GenerationLifetime,
			ReceiveGrace:       lifecycle.ReceiveGrace,
		},
		Peers: []server.PeerConfig{{TunnelIPv4: clientIP}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if serverCore.CurrentSession(clientIP) != nil {
		t.Fatal("cold-start server unexpectedly has a current Session")
	}

	const sessionID uint64 = 0xb401
	var c2s, s2c [32]byte
	for i := range c2s {
		c2s[i] = byte(0x71 + i)
		s2c[i] = byte(0xb1 + i)
	}
	materialA := establishment.TrafficSessionMaterial{
		SessionID: sessionID,
		C2S:       c2s,
		S2C:       s2c,
	}
	serverA, err := establishment.NewServerSession(materialA)
	if err != nil {
		t.Fatalf("NewServerSession(A): %v", err)
	}

	dev := newClientRuntimeTestTun()
	runtime, err := NewClientRuntime(
		dev,
		clientConn,
		clientCore,
		dataplane.ReferenceTunnelMTU,
		ClientRuntimeConfig{},
	)
	if err != nil {
		t.Fatalf("NewClientRuntime: %v", err)
	}

	response := []byte("controller-cold-start-a-established")
	controller, err := client.NewSessionController(
		clientCore,
		runtime,
		&clientRuntimeControllerFactory{
			serverEndpoint: serverEndpoint,
			response:       response,
			material:       materialA,
		},
		client.SessionControllerConfig{
			SoftRekeyAfter:        20 * time.Second,
			EstablishmentRetryMin: time.Second,
			EstablishmentRetryMax: time.Second,
		},
	)
	if err != nil {
		t.Fatalf("NewSessionController: %v", err)
	}
	if err := runtime.SetDatagramDemux(controller); err != nil {
		t.Fatalf("SetDatagramDemux(controller): %v", err)
	}

	runtimeDone := make(chan error, 1)
	go func() { runtimeDone <- runtime.Run() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(ctx) }()

	select {
	case <-runtime.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("client runtime did not become ready")
	}

	// With no initial Session, controller must begin establishment immediately;
	// no external RequestRekey/bootstrap path is required.
	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(establishment): %v", err)
	}
	buf := make([]byte, 2048)
	n, clientEndpoint, err := serverConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("read cold-start establishment request: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("controller-rekey-b")) {
		t.Fatalf("cold-start establishment request=%q", buf[:n])
	}
	if err := serverCore.InstallPendingSession(clientIP, serverA); err != nil {
		t.Fatalf("InstallPendingSession(A): %v", err)
	}
	if _, err := serverConn.WriteToUDPAddrPort(response, clientEndpoint); err != nil {
		t.Fatalf("write cold-start establishment response: %v", err)
	}

	// Successful first install must make TX available and unconditionally emit
	// encrypted activation through the shared TXEngine.
	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(activation): %v", err)
	}
	n, source, err := serverConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("read cold-start activation: %v", err)
	}
	serverScratch, err := serverCore.NewDataScratch()
	if err != nil {
		t.Fatalf("server.NewDataScratch: %v", err)
	}
	inbound, _, _, err := serverCore.HandleNetworkDatagramInPlace(serverScratch, source, buf[:n])
	if err != nil {
		t.Fatalf("server cold-start activation receive: %v", err)
	}
	if inbound.Kind != dataplane.InboundKeepalive || inbound.KeepaliveID != 0 {
		t.Fatalf("cold-start activation=%+v, want KEEPALIVE id 0", inbound)
	}
	if n < dataplane.MinGeneratedEstablishmentWirePacketSize || n > dataplane.MaxGeneratedEstablishmentWirePacketSize {
		t.Fatalf("cold-start activation wire size=%d, want [%d, %d]", n, dataplane.MinGeneratedEstablishmentWirePacketSize, dataplane.MaxGeneratedEstablishmentWirePacketSize)
	}
	if clientCore.Session() == nil || clientCore.Session().ID() != sessionID {
		t.Fatalf("client current after cold start=%v, want %#x", clientCore.Session(), sessionID)
	}
	if serverCore.CurrentSession(clientIP) != serverA {
		t.Fatal("cold-start activation did not promote server pending A")
	}

	toServer := clientRuntimeIPv4Packet(t, clientIP, serverIP, []byte("first DATA after cold start"))
	dev.Inject(toServer)
	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(DATA): %v", err)
	}
	n, source, err = serverConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("read cold-start DATA(A): %v", err)
	}
	opened, err := serverCore.HandleDatagramInPlace(serverScratch, source, buf[:n])
	if err != nil {
		t.Fatalf("server cold-start DATA(A): %v", err)
	}
	if !bytes.Equal(opened, toServer) {
		t.Fatal("cold-start DATA did not use installed generation A")
	}

	_ = dev.Close()
	select {
	case runtimeErr := <-runtimeDone:
		if !errors.Is(runtimeErr, os.ErrClosed) {
			t.Fatalf("runtime error=%v, want os.ErrClosed", runtimeErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not stop after cold-start test")
	}
	select {
	case err := <-controllerDone:
		if err != nil {
			t.Fatalf("controller error after cold-start shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("controller did not stop with cold-start runtime")
	}
}

func clientRuntimeSessionPair(
	t *testing.T,
	sessionID uint64,
	seed byte,
) (*dataplane.Session, *dataplane.Session) {
	t.Helper()
	var c2s, s2c [32]byte
	for i := 0; i < 32; i++ {
		c2s[i] = seed + byte(i)
		s2c[i] = seed + 0x40 + byte(i)
	}
	clientSession, err := dataplane.NewSession(sessionID, c2s, s2c, 0)
	if err != nil {
		t.Fatalf("NewSession(client %#x): %v", sessionID, err)
	}
	serverSession, err := dataplane.NewSession(sessionID, s2c, c2s, 0)
	if err != nil {
		t.Fatalf("NewSession(server %#x): %v", sessionID, err)
	}
	return clientSession, serverSession
}
