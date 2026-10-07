package noisehandshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/establishment"
	coreserver "github.com/noranite/Noranite-l3/internal/server"
)

func TestNoiseServerAuthenticatedClientInstallsConfiguredPeerBeforeResponse(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	clientPublic, err := PublicKeyFromPrivate(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := PublicKeyFromPrivate(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}

	peerA := netip.MustParseAddr("10.66.0.2")
	peerB := netip.MustParseAddr("10.66.0.3")
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0x20 + i)
	}
	core := newNoiseTestCore(t, routeKey, peerA, peerB)

	serverRandom := append(sessionIDBytes(0x8877665544332211), testEntropy(0x41)...)
	serverRandom = append(serverRandom, generatedResponseRandomBytes()...)
	provider, err := NewServer(ServerConfig{
		Core:             core,
		StaticPrivateKey: serverPrivate,
		Peers: []AuthorizedPeer{{
			TunnelIPv4: peerB,
			PublicKey:  clientPublic,
		}},
		Random: bytes.NewReader(serverRandom),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	freshness := testFreshness(1_700_000_000, 1)
	initPacket, clientHandshake := makeNoiseTestInit(t, clientPrivate, serverPublic, 77, freshness, 0x81, routeKey)
	source := netip.MustParseAddrPort("192.0.2.10:51820")

	handled, response, destination, err := handleNoiseTestServer(provider, source, initPacket)
	if err != nil {
		t.Fatalf("TryHandleEstablishmentDatagramInPlace: %v", err)
	}
	if !handled {
		t.Fatal("Noise INIT was not handled")
	}
	if destination != source {
		t.Fatalf("response destination=%v, want %v", destination, source)
	}
	if len(response) < ResponseMinGeneratedPacketSize || len(response) > len(initPacket) {
		t.Fatalf("response size=%d, want [%d, %d]", len(response), ResponseMinGeneratedPacketSize, len(initPacket))
	}

	material := finishNoiseTestClient(t, clientHandshake, response, routeKey)

	// A returned RESPONSE is observable only after InstallPendingSession has
	// published this session_id into Core's global registry.
	duplicate, err := establishment.NewServerSession(material)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.InstallPendingSession(peerA, duplicate); !errors.Is(err, coreserver.ErrSessionIDCollision) {
		t.Fatalf("same session id after RESPONSE: error=%v, want ErrSessionIDCollision", err)
	}

	// Prove that authenticated public-key authorization selected peerB rather
	// than source UDP identity or another configured tunnel peer. A packet whose
	// inner source is peerB must authenticate under the newly pending session and
	// promote it; the same Session installed for peerA would reject that source.
	clientSession, err := establishment.NewClientSession(material)
	if err != nil {
		t.Fatal(err)
	}
	clientScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatal(err)
	}
	serverScratch, err := core.NewDataScratch()
	if err != nil {
		t.Fatal(err)
	}
	inner := noiseTestIPv4Packet(peerB, netip.MustParseAddr("10.66.0.1"), []byte("authorized mapping"))
	wire, _, err := clientSession.SealDataToWithPadding(clientScratch, make([]byte, 0, len(inner)+dataplane.DataOverhead), inner, 0)
	if err != nil {
		t.Fatalf("SealDataToWithPadding: %v", err)
	}
	got, err := core.HandleDatagramInPlace(serverScratch, source, wire)
	if err != nil {
		t.Fatalf("Core.HandleDatagramInPlace: %v", err)
	}
	if !bytes.Equal(got, inner) {
		t.Fatalf("inner packet mismatch after mapped pending promotion")
	}
}

func TestNoiseServerUnknownAuthenticatedClientIsSilentAndDoesNotUseResponseRNG(t *testing.T) {
	authorizedPrivate := testPrivateKey(1)
	unknownPrivate := testPrivateKey(65)
	serverPrivate := testPrivateKey(33)
	authorizedPublic, _ := PublicKeyFromPrivate(authorizedPrivate)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	peerIP := netip.MustParseAddr("10.66.0.2")
	core := newNoiseTestCore(t, [32]byte{}, peerIP)

	reader := &countingReader{r: bytes.NewReader(testEntropy(0x41))}
	provider, err := NewServer(ServerConfig{
		Core:             core,
		StaticPrivateKey: serverPrivate,
		Peers:            []AuthorizedPeer{{TunnelIPv4: peerIP, PublicKey: authorizedPublic}},
		Random:           reader,
	})
	if err != nil {
		t.Fatal(err)
	}

	packet, _ := makeNoiseTestInit(t, unknownPrivate, serverPublic, 1, testFreshness(10, 0), 0x81)
	handled, response, _, err := handleNoiseTestServer(provider, netip.MustParseAddrPort("192.0.2.1:1000"), packet)
	if err != nil {
		t.Fatalf("unknown authenticated client returned error: %v", err)
	}
	if !handled || len(response) != 0 {
		t.Fatalf("handled=%v response=%d, want silent consume", handled, len(response))
	}
	if reader.BytesRead() != 0 {
		t.Fatalf("server response RNG consumed %d bytes for unauthorized client", reader.BytesRead())
	}
}

func TestNoiseServerSameFreshnessReplayDropsBeforeResponseRNG(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	clientPublic, _ := PublicKeyFromPrivate(clientPrivate)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	peerIP := netip.MustParseAddr("10.66.0.2")
	core := newNoiseTestCore(t, [32]byte{}, peerIP)

	firstRandom := append(sessionIDBytes(101), testEntropy(0x41)...)
	firstRandom = append(firstRandom, generatedResponseRandomBytes()...)
	rng := &switchableReader{r: bytes.NewReader(firstRandom)}
	provider, err := NewServer(ServerConfig{
		Core:             core,
		StaticPrivateKey: serverPrivate,
		Peers:            []AuthorizedPeer{{TunnelIPv4: peerIP, PublicKey: clientPublic}},
		Random:           rng,
	})
	if err != nil {
		t.Fatal(err)
	}

	freshness := testFreshness(100, 5)
	first, _ := makeNoiseTestInit(t, clientPrivate, serverPublic, 1, freshness, 0x81)
	if _, response, _, err := handleNoiseTestServer(provider, netip.MustParseAddrPort("192.0.2.1:1000"), first); err != nil || len(response) == 0 {
		t.Fatalf("first handshake response=%d err=%v", len(response), err)
	}

	rng.Fail()
	replay, _ := makeNoiseTestInit(t, clientPrivate, serverPublic, 2, freshness, 0x91)
	handled, response, _, err := handleNoiseTestServer(provider, netip.MustParseAddrPort("192.0.2.1:1000"), replay)
	if err != nil {
		t.Fatalf("stale replay reached RNG/local failure: %v", err)
	}
	if !handled || len(response) != 0 {
		t.Fatalf("stale replay handled=%v response=%d", handled, len(response))
	}
}

func TestNoiseServerSessionIDCollisionDoesNotAdvanceFreshness(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	clientPublic, _ := PublicKeyFromPrivate(clientPrivate)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	peerIP := netip.MustParseAddr("10.66.0.2")

	const collidingID = uint64(0x1111222233334444)
	initial, err := dataplane.NewSession(collidingID, [32]byte{1}, [32]byte{2}, 0)
	if err != nil {
		t.Fatal(err)
	}
	core := newNoiseTestCoreWithInitial(t, [32]byte{}, peerIP, initial)

	const secondID = uint64(0x5555666677778888)
	randomBytes := append(sessionIDBytes(collidingID), testEntropy(0x41)...)
	randomBytes = append(randomBytes, sessionIDBytes(secondID)...)
	randomBytes = append(randomBytes, testEntropy(0x61)...)
	randomBytes = append(randomBytes, generatedResponseRandomBytes()...)
	provider, err := NewServer(ServerConfig{
		Core:             core,
		StaticPrivateKey: serverPrivate,
		Peers:            []AuthorizedPeer{{TunnelIPv4: peerIP, PublicKey: clientPublic}},
		Random:           bytes.NewReader(randomBytes),
	})
	if err != nil {
		t.Fatal(err)
	}

	freshness := testFreshness(200, 1)
	packet1, _ := makeNoiseTestInit(t, clientPrivate, serverPublic, 1, freshness, 0x81)
	handled, response, _, err := handleNoiseTestServer(provider, netip.MustParseAddrPort("192.0.2.1:1000"), packet1)
	if err != nil {
		t.Fatalf("collision should be silent exchange drop: %v", err)
	}
	if !handled || len(response) != 0 {
		t.Fatalf("collision handled=%v response=%d", handled, len(response))
	}

	// The exact same freshness must remain eligible because failed installation
	// did not advance latestFreshness.
	packet2, clientHandshake2 := makeNoiseTestInit(t, clientPrivate, serverPublic, 2, freshness, 0x91)
	_, response, _, err = handleNoiseTestServer(provider, netip.MustParseAddrPort("192.0.2.1:1000"), packet2)
	if err != nil {
		t.Fatalf("retry after collision: %v", err)
	}
	if len(response) == 0 {
		t.Fatal("retry with same freshness was incorrectly made stale by collision")
	}
	material := finishNoiseTestClient(t, clientHandshake2, response)
	if material.SessionID != secondID {
		t.Fatalf("retry session id=%#x, want %#x", material.SessionID, secondID)
	}
}

func TestNoiseServerMalformedOrUnauthenticatedInitIsSilent(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	clientPublic, _ := PublicKeyFromPrivate(clientPrivate)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	peerIP := netip.MustParseAddr("10.66.0.2")
	core := newNoiseTestCore(t, [32]byte{}, peerIP)
	provider, err := NewServer(ServerConfig{
		Core:             core,
		StaticPrivateKey: serverPrivate,
		Peers:            []AuthorizedPeer{{TunnelIPv4: peerIP, PublicKey: clientPublic}},
		Random:           bytes.NewReader(testEntropy(0x41)),
	})
	if err != nil {
		t.Fatal(err)
	}

	packet, _ := makeNoiseTestInit(t, clientPrivate, serverPublic, 9, testFreshness(10, 1), 0x81)
	packet[len(packet)-17] ^= 0x80
	handled, response, _, err := handleNoiseTestServer(provider, netip.MustParseAddrPort("192.0.2.1:1000"), packet)
	if err != nil {
		t.Fatalf("bit-flipped INIT returned local error: %v", err)
	}
	if !handled || len(response) != 0 {
		t.Fatalf("bit-flipped INIT handled=%v response=%d", handled, len(response))
	}

	malformed := append([]byte(nil), packet...)
	malformed[len(malformed)-18] ^= 0x40
	handled, response, _, err = handleNoiseTestServer(provider, netip.MustParseAddrPort("192.0.2.1:1000"), malformed)
	if err != nil || !handled || len(response) != 0 {
		t.Fatalf("malformed owned INIT handled=%v response=%d err=%v", handled, len(response), err)
	}
}

func TestNoiseServerRNGFailureIsLocalError(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	clientPublic, _ := PublicKeyFromPrivate(clientPrivate)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	peerIP := netip.MustParseAddr("10.66.0.2")
	core := newNoiseTestCore(t, [32]byte{}, peerIP)
	provider, err := NewServer(ServerConfig{
		Core:             core,
		StaticPrivateKey: serverPrivate,
		Peers:            []AuthorizedPeer{{TunnelIPv4: peerIP, PublicKey: clientPublic}},
		Random:           errorReader{err: io.ErrUnexpectedEOF},
	})
	if err != nil {
		t.Fatal(err)
	}
	packet, _ := makeNoiseTestInit(t, clientPrivate, serverPublic, 1, testFreshness(1, 0), 0x81)
	_, _, _, err = handleNoiseTestServer(provider, netip.MustParseAddrPort("192.0.2.1:1000"), packet)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("RNG error=%v, want io.ErrUnexpectedEOF", err)
	}
}

func TestNoiseServerFinalFreshnessRecheckRejectsOlderCompletion(t *testing.T) {
	serverPrivate := testPrivateKey(33)
	clientPrivate := testPrivateKey(1)
	clientPublic, _ := PublicKeyFromPrivate(clientPrivate)
	peerIP := netip.MustParseAddr("10.66.0.2")
	core := newNoiseTestCore(t, [32]byte{}, peerIP)
	provider, err := NewServer(ServerConfig{
		Core:             core,
		StaticPrivateKey: serverPrivate,
		Peers:            []AuthorizedPeer{{TunnelIPv4: peerIP, PublicKey: clientPublic}},
		Random:           bytes.NewReader(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := provider.peers[clientPublic]

	newerSession, err := dataplane.NewSession(11, [32]byte{1}, [32]byte{2}, 0)
	if err != nil {
		t.Fatal(err)
	}
	olderSession, err := dataplane.NewSession(10, [32]byte{3}, [32]byte{4}, 0)
	if err != nil {
		t.Fatal(err)
	}
	newer := testFreshness(11, 0)
	older := testFreshness(10, 0)

	installed, err := provider.commitFreshPending(peer, newer, newerSession)
	if err != nil || !installed {
		t.Fatalf("commit newer installed=%v err=%v", installed, err)
	}
	installed, err = provider.commitFreshPending(peer, older, olderSession)
	if err != nil {
		t.Fatalf("commit older: %v", err)
	}
	if installed {
		t.Fatal("older completion superseded newer freshness")
	}
	if peer.latestFreshness != newer {
		t.Fatalf("latest freshness=%x, want %x", peer.latestFreshness, newer)
	}
}

func TestNoiseServerRejectsZeroStaticPrivateKey(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	clientPublic, _ := PublicKeyFromPrivate(clientPrivate)
	peerIP := netip.MustParseAddr("10.66.0.2")
	core := newNoiseTestCore(t, [32]byte{}, peerIP)

	_, err := NewServer(ServerConfig{
		Core:             core,
		StaticPrivateKey: PrivateKey{},
		Peers:            []AuthorizedPeer{{TunnelIPv4: peerIP, PublicKey: clientPublic}},
	})
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("zero server private key error=%v, want ErrInvalidKey", err)
	}
}

func TestNoiseServerConstructorRejectsInconsistentAuthorization(t *testing.T) {
	serverPrivate := testPrivateKey(33)
	clientPrivateA := testPrivateKey(1)
	clientPrivateB := testPrivateKey(65)
	clientPublicA, _ := PublicKeyFromPrivate(clientPrivateA)
	clientPublicB, _ := PublicKeyFromPrivate(clientPrivateB)
	peerA := netip.MustParseAddr("10.66.0.2")
	peerB := netip.MustParseAddr("10.66.0.3")
	core := newNoiseTestCore(t, [32]byte{}, peerA, peerB)

	tests := []struct {
		name  string
		peers []AuthorizedPeer
		want  error
	}{
		{
			name: "duplicate public key",
			peers: []AuthorizedPeer{
				{TunnelIPv4: peerA, PublicKey: clientPublicA},
				{TunnelIPv4: peerB, PublicKey: clientPublicA},
			},
			want: ErrInvalidKey,
		},
		{
			name: "duplicate tunnel",
			peers: []AuthorizedPeer{
				{TunnelIPv4: peerA, PublicKey: clientPublicA},
				{TunnelIPv4: peerA, PublicKey: clientPublicB},
			},
			want: ErrInvalidState,
		},
		{
			name:  "unknown core peer",
			peers: []AuthorizedPeer{{TunnelIPv4: netip.MustParseAddr("10.66.0.99"), PublicKey: clientPublicA}},
			want:  coreserver.ErrUnknownPeer,
		},
		{
			name:  "low order public key",
			peers: []AuthorizedPeer{{TunnelIPv4: peerA, PublicKey: PublicKey{}}},
			want:  ErrInvalidKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewServer(ServerConfig{
				Core:             core,
				StaticPrivateKey: serverPrivate,
				Peers:            test.peers,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("NewServer error=%v, want %v", err, test.want)
			}
		})
	}
}

func TestNoiseServerSerializesInjectedRandomReader(t *testing.T) {
	serverPrivate := testPrivateKey(33)
	clientPrivate := testPrivateKey(1)
	clientPublic, _ := PublicKeyFromPrivate(clientPrivate)
	peerIP := netip.MustParseAddr("10.66.0.2")
	core := newNoiseTestCore(t, [32]byte{}, peerIP)
	detector := &concurrencyDetectReader{}
	provider, err := NewServer(ServerConfig{
		Core:             core,
		StaticPrivateKey: serverPrivate,
		Peers:            []AuthorizedPeer{{TunnelIPv4: peerIP, PublicKey: clientPublic}},
		Random:           detector,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := provider.generateSessionID(); err != nil {
				t.Errorf("generateSessionID: %v", err)
			}
		}()
	}
	wg.Wait()
	if detector.concurrent.Load() {
		t.Fatal("injected Random observed concurrent Read calls")
	}
}

func newNoiseTestCore(t *testing.T, routeKey [32]byte, peers ...netip.Addr) *coreserver.Core {
	t.Helper()
	configs := make([]coreserver.PeerConfig, 0, len(peers))
	for _, peer := range peers {
		configs = append(configs, coreserver.PeerConfig{TunnelIPv4: peer})
	}
	core, err := coreserver.New(coreserver.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: 1380,
		Lifecycle: coreserver.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: configs,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return core
}

func newNoiseTestCoreWithInitial(t *testing.T, routeKey [32]byte, peer netip.Addr, initial *dataplane.Session) *coreserver.Core {
	t.Helper()
	core, err := coreserver.New(coreserver.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: 1380,
		Lifecycle: coreserver.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: []coreserver.PeerConfig{{TunnelIPv4: peer, InitialSession: initial}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return core
}

func makeNoiseTestInit(
	t *testing.T,
	clientPrivate PrivateKey,
	serverPublic PublicKey,
	exchangeID uint64,
	freshness Freshness,
	entropyStart byte,
	routeKeys ...[32]byte,
) ([]byte, *noise.HandshakeState) {
	t.Helper()
	client, err := newInitiatorHandshake(clientPrivate, serverPublic, exchangeID, bytes.NewReader(testEntropy(entropyStart)))
	if err != nil {
		t.Fatalf("newInitiatorHandshake: %v", err)
	}
	message, cs1, cs2, err := client.WriteMessage(nil, encodeFreshness(freshness))
	if err != nil {
		t.Fatalf("client WriteMessage: %v", err)
	}
	if cs1 != nil || cs2 != nil {
		t.Fatal("IK unexpectedly completed after INIT")
	}
	var routeKey [32]byte
	if len(routeKeys) != 0 {
		routeKey = routeKeys[0]
	}
	scratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := appendInitPacket(
		make([]byte, 0, InitMaxGeneratedPacketSize),
		scratch,
		bytes.NewReader(generatedInitRandomBytes()),
		exchangeID,
		message,
	)
	if err != nil {
		t.Fatalf("appendInitPacket: %v", err)
	}
	return packet, client
}

func finishNoiseTestClient(
	t *testing.T,
	client *noise.HandshakeState,
	response []byte,
	routeKeys ...[32]byte,
) establishment.TrafficSessionMaterial {
	t.Helper()
	var routeKey [32]byte
	if len(routeKeys) != 0 {
		routeKey = routeKeys[0]
	}
	scratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatal(err)
	}
	route, err := dataplane.DecodeRoute(scratch, response)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := parseResponsePacket(scratch, route, true, response)
	if err != nil {
		t.Fatalf("parseResponsePacket: %v", err)
	}
	payload, cs1, cs2, err := client.ReadMessage(nil, wire.message)
	if err != nil {
		t.Fatalf("client ReadMessage: %v", err)
	}
	sessionID, err := parseResponsePayload(payload)
	if err != nil {
		t.Fatalf("parseResponsePayload: %v", err)
	}
	material, err := trafficMaterialFromSplit(sessionID, cs1, cs2)
	if err != nil {
		t.Fatalf("trafficMaterialFromSplit: %v", err)
	}
	return material
}

func handleNoiseTestServer(
	provider *Server,
	source netip.AddrPort,
	packet []byte,
) (bool, []byte, netip.AddrPort, error) {
	provider.routeMu.Lock()
	route, err := dataplane.DecodeRoute(provider.routeScratch, packet)
	provider.routeMu.Unlock()
	routeDecoded := err == nil
	if err != nil {
		route = dataplane.Route{}
	}
	return provider.TryHandleEstablishmentDatagramInPlace(source, route, routeDecoded, packet)
}

func noiseTestIPv4Packet(source, destination netip.Addr, payload []byte) []byte {
	src := source.As4()
	dst := destination.As4()
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	copy(packet[20:], payload)
	return packet
}

func sessionIDBytes(sessionID uint64) []byte {
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], sessionID)
	return raw[:]
}

func generatedInitRandomBytes() []byte {
	paddingLength := InitMinGeneratedPacketSize - InitMinPacketSize
	return append([]byte{0, 0}, make([]byte, paddingLength)...)
}

func generatedResponseRandomBytes() []byte {
	paddingLength := ResponseMinGeneratedPacketSize - ResponseMinPacketSize
	return make([]byte, paddingLength)
}

type countingReader struct {
	mu sync.Mutex
	r  io.Reader
	n  int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.r.Read(p)
	r.n += n
	return n, err
}

func (r *countingReader) BytesRead() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

type switchableReader struct {
	mu   sync.Mutex
	r    io.Reader
	fail bool
}

func (r *switchableReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return 0, io.ErrUnexpectedEOF
	}
	return r.r.Read(p)
}

func (r *switchableReader) Fail() {
	r.mu.Lock()
	r.fail = true
	r.mu.Unlock()
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type concurrencyDetectReader struct {
	active     atomic.Int32
	concurrent atomic.Bool
}

func (r *concurrencyDetectReader) Read(p []byte) (int, error) {
	if r.active.Add(1) != 1 {
		r.concurrent.Store(true)
	}
	time.Sleep(200 * time.Microsecond)
	for i := range p {
		p[i] = 1
	}
	r.active.Add(-1)
	return len(p), nil
}
