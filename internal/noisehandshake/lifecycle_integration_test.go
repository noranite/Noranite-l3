package noisehandshake

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	coreclient "github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
	coreserver "github.com/noranite/Noranite-l3/internal/server"
)

const lifecycleTestTimeout = 2 * time.Second

type noiseLifecycleHarness struct {
	clientCore *coreclient.Core
	serverCore *coreserver.Core
	clientHS   *Client
	serverHS   *Server
	controller *coreclient.SessionController
	runtime    *noiseClientControllerRuntime

	routeKey       [32]byte
	clientIP       netip.Addr
	serverIP       netip.Addr
	clientEndpoint netip.AddrPort
	serverEndpoint netip.AddrPort

	cancel context.CancelFunc
	runErr chan error
}

func TestNoiseLifecycleColdStartActivatesPendingGeneration(t *testing.T) {
	h := newNoiseLifecycleHarness(t,
		lifecycleClientRandom(
			clientExchange(0x101, 0x81),
		),
		lifecycleServerRandom(
			serverExchange(0xa001, 0x41),
		),
		5*time.Second,
	)
	defer h.close(t)

	init := h.waitInit(t)
	response := h.processInit(t, init)
	if current := h.serverCore.CurrentSession(h.clientIP); current != nil {
		t.Fatalf("server current before activation=%#x, want nil", current.ID())
	}

	h.deliverResponse(t, response)
	if current := h.clientCore.Session(); current == nil || current.ID() != 0xa001 {
		t.Fatalf("client current=%v, want session %#x", current, uint64(0xa001))
	}

	keepalive := h.waitTransport(t)
	if current := h.serverCore.CurrentSession(h.clientIP); current != nil {
		t.Fatalf("server current before KEEPALIVE=%#x, want nil", current.ID())
	}
	h.deliverTransport(t, keepalive, true)

	if current := h.serverCore.CurrentSession(h.clientIP); current == nil || current.ID() != 0xa001 {
		t.Fatalf("server current after KEEPALIVE=%v, want session %#x", current, uint64(0xa001))
	}

	h.assertClientToServerData(t, "cold-start c2s")
	h.assertServerToClientData(t, "cold-start s2c")
}

func TestNoiseLifecycleLiveRekeyKeepsAUntilBTrafficAndSurvivesLostActivation(t *testing.T) {
	h := newNoiseLifecycleHarness(t,
		lifecycleClientRandom(
			clientExchange(0x201, 0x81),
			clientExchange(0x202, 0xa1),
		),
		lifecycleServerRandom(
			serverExchange(0xb001, 0x41),
			serverExchange(0xb002, 0x61),
		),
		5*time.Second,
	)
	defer h.close(t)

	h.establishCurrent(t, 0xb001)
	h.controller.RequestRekey()

	initB := h.waitInit(t)
	responseB := h.processInit(t, initB)
	if current := h.serverCore.CurrentSession(h.clientIP); current == nil || current.ID() != 0xb001 {
		t.Fatalf("server current while B pending=%v, want A %#x", current, uint64(0xb001))
	}
	if current := h.clientCore.Session(); current == nil || current.ID() != 0xb001 {
		t.Fatalf("client current before B response=%v, want A %#x", current, uint64(0xb001))
	}

	// Establishment B must not interrupt the already active generation A.
	h.assertClientToServerData(t, "A remains live during B handshake")
	h.assertServerToClientData(t, "A reverse remains live during B handshake")

	h.deliverResponse(t, responseB)
	if current := h.clientCore.Session(); current == nil || current.ID() != 0xb002 {
		t.Fatalf("client current after B response=%v, want B %#x", current, uint64(0xb002))
	}
	if current := h.serverCore.CurrentSession(h.clientIP); current == nil || current.ID() != 0xb001 {
		t.Fatalf("server current before B transport=%v, want A %#x", current, uint64(0xb001))
	}

	// Deliberately lose the controller's activation KEEPALIVE. The next ordinary DATA
	// under B must prove key possession and promote server pending B.
	_ = h.waitTransport(t)
	h.assertClientToServerData(t, "DATA B promotes after lost KEEPALIVE")
	if current := h.serverCore.CurrentSession(h.clientIP); current == nil || current.ID() != 0xb002 {
		t.Fatalf("server current after DATA(B)=%v, want B %#x", current, uint64(0xb002))
	}
	h.assertServerToClientData(t, "B reverse after DATA promotion")
}

func TestNoiseLifecycleLostResponseRetriesFreshExchangeAndDropsLateResponse(t *testing.T) {
	const retry = 120 * time.Millisecond
	h := newNoiseLifecycleHarness(t,
		lifecycleClientRandom(
			clientExchange(0x301, 0x81),
			clientExchange(0x302, 0xa1),
			clientExchange(0x303, 0xc1),
		),
		lifecycleServerRandom(
			serverExchange(0xc001, 0x41),
			serverExchange(0xc002, 0x61),
			serverExchange(0xc003, 0x71),
		),
		retry,
	)
	defer h.close(t)

	h.establishCurrent(t, 0xc001)
	h.controller.RequestRekey()

	initH1 := h.waitInit(t)
	responseH1 := h.processInit(t, initH1) // server pending B; response is lost
	if current := h.clientCore.Session(); current == nil || current.ID() != 0xc001 {
		t.Fatalf("client changed after lost response: %v", current)
	}
	if current := h.serverCore.CurrentSession(h.clientIP); current == nil || current.ID() != 0xc001 {
		t.Fatalf("server current changed while response lost: %v", current)
	}
	h.assertClientToServerData(t, "A works while RESPONSE(H1) is lost")

	initH2 := h.waitInit(t)
	wireH1, err := parseLifecycleInit(h.routeKey, initH1.Packet)
	if err != nil {
		t.Fatal(err)
	}
	wireH2, err := parseLifecycleInit(h.routeKey, initH2.Packet)
	if err != nil {
		t.Fatal(err)
	}
	if wireH1.exchangeID == wireH2.exchangeID {
		t.Fatalf("retry reused exchange id %#x", wireH1.exchangeID)
	}
	if bytes.Equal(initH1.Packet, initH2.Packet) {
		t.Fatal("retry retransmitted identical INIT")
	}

	responseH2 := h.processInit(t, initH2)

	// H1 response is valid cryptographically but no longer belongs to the active
	// exchange. It is consumed before Noise processing and cannot install B.
	h.deliverResponse(t, responseH1)
	if current := h.clientCore.Session(); current == nil || current.ID() != 0xc001 {
		t.Fatalf("late RESPONSE(H1) changed client current: %v", current)
	}
	h.assertNoTransport(t, 25*time.Millisecond)

	h.deliverResponse(t, responseH2)
	if current := h.clientCore.Session(); current == nil || current.ID() != 0xc003 {
		t.Fatalf("client current after RESPONSE(H2)=%v, want %#x", current, uint64(0xc003))
	}
	keepalive := h.waitTransport(t)

	// Lifetime classifier remains authoritative after attempt completion.
	h.deliverResponse(t, responseH1)
	if current := h.clientCore.Session(); current == nil || current.ID() != 0xc003 {
		t.Fatalf("post-completion late response changed current: %v", current)
	}
	h.assertNoTransport(t, 25*time.Millisecond)

	h.deliverTransport(t, keepalive, false)
	if current := h.serverCore.CurrentSession(h.clientIP); current == nil || current.ID() != 0xc003 {
		t.Fatalf("server current after H2 activation=%v, want %#x", current, uint64(0xc003))
	}
}

func TestNoiseLifecycleRejectedRekeyResponseLeavesCurrentGenerationUntouched(t *testing.T) {
	h := newNoiseLifecycleHarness(t,
		lifecycleClientRandom(
			clientExchange(0x401, 0x81),
			clientExchange(0x402, 0xa1),
		),
		lifecycleServerRandom(
			serverExchange(0xd001, 0x41),
			serverExchange(0xd002, 0x61),
		),
		5*time.Second,
	)
	defer h.close(t)

	h.establishCurrent(t, 0xd001)
	h.controller.RequestRekey()
	initB := h.waitInit(t)
	responseB := h.processInit(t, initB)

	bad := append([]byte(nil), responseB...)
	bad[len(bad)-17] ^= 0x80
	h.deliverResponse(t, bad)
	if current := h.clientCore.Session(); current == nil || current.ID() != 0xd001 {
		t.Fatalf("rejected rekey response mutated current A: %v", current)
	}
	h.assertNoTransport(t, 25*time.Millisecond)
	h.assertClientToServerData(t, "A survives rejected rekey response")
	h.assertServerToClientData(t, "A reverse survives rejected rekey response")

	// The malformed response must not poison the live attempt. The authentic B
	// response for the same exchange can still complete normally.
	h.deliverResponse(t, responseB)
	if current := h.clientCore.Session(); current == nil || current.ID() != 0xd002 {
		t.Fatalf("valid B response after rejection did not install B: %v", current)
	}
	h.deliverTransport(t, h.waitTransport(t), false)
}

func TestNoiseLifecycleNewerRetryMakesDelayedOlderInitStale(t *testing.T) {
	const retry = 120 * time.Millisecond
	h := newNoiseLifecycleHarness(t,
		lifecycleClientRandom(
			clientExchange(0x501, 0x81),
			clientExchange(0x502, 0xa1),
			clientExchange(0x503, 0xc1),
		),
		lifecycleServerRandom(
			serverExchange(0xe001, 0x41),
			serverExchange(0xe003, 0x61),
		),
		retry,
	)
	defer h.close(t)

	h.establishCurrent(t, 0xe001)
	h.controller.RequestRekey()
	older := h.waitInit(t)
	newer := h.waitInit(t) // retry occurs while older INIT is delayed in network

	newerResponse := h.processInit(t, newer)
	olderResponse := h.processInit(t, older)
	if len(olderResponse) != 0 {
		t.Fatal("delayed older INIT produced RESPONSE after newer freshness committed")
	}

	h.deliverResponse(t, newerResponse)
	if current := h.clientCore.Session(); current == nil || current.ID() != 0xe003 {
		t.Fatalf("newer retry did not become client current: %v", current)
	}
	h.deliverTransport(t, h.waitTransport(t), false)
	if current := h.serverCore.CurrentSession(h.clientIP); current == nil || current.ID() != 0xe003 {
		t.Fatalf("newer retry did not become server current: %v", current)
	}
}

func newNoiseLifecycleHarness(
	t *testing.T,
	clientRandom []byte,
	serverRandom []byte,
	retry time.Duration,
) *noiseLifecycleHarness {
	t.Helper()

	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0x90 + i)
	}
	clientIP := netip.MustParseAddr("10.66.0.2")
	serverIP := netip.MustParseAddr("10.66.0.1")
	clientEndpoint := netip.MustParseAddrPort("198.51.100.20:40000")
	serverEndpoint := netip.MustParseAddrPort("192.0.2.10:41675")
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

	clientCore, err := coreclient.New(coreclient.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: coreclient.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Session: nil,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	serverCore, err := coreserver.New(coreserver.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: coreserver.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: []coreserver.PeerConfig{{TunnelIPv4: clientIP}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	clientHS, err := NewClient(ClientConfig{
		ServerEndpoint:   serverEndpoint,
		RouteKey:         routeKey,
		StaticPrivateKey: clientPrivate,
		ServerPublicKey:  serverPublic,
		Random:           bytes.NewReader(clientRandom),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	serverHS, err := NewServer(ServerConfig{
		Core:             serverCore,
		StaticPrivateKey: serverPrivate,
		Peers:            []AuthorizedPeer{{TunnelIPv4: clientIP, PublicKey: clientPublic}},
		Random:           bytes.NewReader(serverRandom),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	runtime := newNoiseClientControllerRuntime()
	controller, err := coreclient.NewSessionController(
		clientCore,
		runtime,
		clientHS,
		coreclient.SessionControllerConfig{
			SoftRekeyAfter:        20 * time.Second,
			EstablishmentRetryMin: retry,
			EstablishmentRetryMax: retry,
		},
	)
	if err != nil {
		t.Fatalf("NewSessionController: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- controller.Run(ctx) }()

	return &noiseLifecycleHarness{
		clientCore:     clientCore,
		serverCore:     serverCore,
		clientHS:       clientHS,
		serverHS:       serverHS,
		controller:     controller,
		runtime:        runtime,
		routeKey:       routeKey,
		clientIP:       clientIP,
		serverIP:       serverIP,
		clientEndpoint: clientEndpoint,
		serverEndpoint: serverEndpoint,
		cancel:         cancel,
		runErr:         runErr,
	}
}

func (h *noiseLifecycleHarness) close(t *testing.T) {
	t.Helper()
	close(h.runtime.done)
	h.cancel()
	select {
	case err := <-h.runErr:
		if err != nil && err != context.Canceled {
			t.Fatalf("SessionController.Run: %v", err)
		}
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("SessionController did not stop")
	}
}

func (h *noiseLifecycleHarness) waitInit(t *testing.T) coreclient.EstablishmentDatagram {
	t.Helper()
	select {
	case datagram := <-h.runtime.sent:
		if datagram.Destination != h.serverEndpoint {
			t.Fatalf("INIT destination=%v, want %v", datagram.Destination, h.serverEndpoint)
		}
		return datagram
	case err := <-h.runErr:
		t.Fatalf("SessionController stopped before INIT: %v", err)
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("timed out waiting for Noise INIT")
	}
	return coreclient.EstablishmentDatagram{}
}

func (h *noiseLifecycleHarness) processInit(t *testing.T, init coreclient.EstablishmentDatagram) []byte {
	t.Helper()
	packet := append([]byte(nil), init.Packet...)
	scratch, err := dataplane.NewDataScratch(h.routeKey)
	if err != nil {
		t.Fatal(err)
	}
	route, err := dataplane.DecodeRoute(scratch, packet)
	if err != nil {
		t.Fatalf("decode INIT route: %v", err)
	}
	handled, response, destination, err := h.serverHS.TryHandleEstablishmentDatagramInPlace(
		h.clientEndpoint,
		route,
		true,
		packet,
	)
	if err != nil {
		t.Fatalf("server establishment: %v", err)
	}
	if !handled {
		t.Fatal("server provider did not own Noise INIT")
	}
	if len(response) == 0 {
		return nil
	}
	if destination != h.clientEndpoint {
		t.Fatalf("RESPONSE destination=%v, want %v", destination, h.clientEndpoint)
	}
	return append([]byte(nil), response...)
}

func (h *noiseLifecycleHarness) deliverResponse(t *testing.T, response []byte) {
	t.Helper()
	if len(response) == 0 {
		t.Fatal("cannot deliver empty Noise RESPONSE")
	}
	packet := append([]byte(nil), response...)
	scratch, err := dataplane.NewDataScratch(h.routeKey)
	if err != nil {
		t.Fatal(err)
	}
	route, routeErr := dataplane.DecodeRoute(scratch, packet)
	routeDecoded := routeErr == nil
	handled, err := h.controller.HandleDatagram(h.serverEndpoint, route, routeDecoded, packet)
	if err != nil {
		t.Fatalf("client HandleDatagram(RESPONSE): %v", err)
	}
	if !handled {
		t.Fatal("client controller did not consume Noise RESPONSE")
	}
}

func (h *noiseLifecycleHarness) waitTransport(t *testing.T) *coreclient.OutboundOperation {
	t.Helper()
	select {
	case op := <-h.runtime.transport:
		if op == nil {
			t.Fatal("nil activation transport operation")
		}
		return op
	case err := <-h.runErr:
		t.Fatalf("SessionController stopped before activation transport: %v", err)
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("timed out waiting for activation transport")
	}
	return nil
}

func (h *noiseLifecycleHarness) assertNoTransport(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case op := <-h.runtime.transport:
		t.Fatalf("unexpected activation transport for session %#x", op.Session().ID())
	case <-time.After(wait):
	}
}

func (h *noiseLifecycleHarness) deliverTransport(t *testing.T, op *coreclient.OutboundOperation, deliverACK bool) {
	t.Helper()
	clientScratch, err := h.clientCore.NewDataScratch()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := op.SealTo(clientScratch, make([]byte, 0, op.MaxWireSize()))
	if err != nil {
		t.Fatalf("seal activation transport: %v", err)
	}
	if len(wire) < dataplane.MinGeneratedEstablishmentWirePacketSize ||
		len(wire) > dataplane.MaxGeneratedEstablishmentWirePacketSize {
		t.Fatalf("activation wire size=%d, want [%d, %d]", len(wire), dataplane.MinGeneratedEstablishmentWirePacketSize, dataplane.MaxGeneratedEstablishmentWirePacketSize)
	}
	serverScratch, err := h.serverCore.NewDataScratch()
	if err != nil {
		t.Fatal(err)
	}
	inbound, response, destination, err := h.serverCore.HandleNetworkDatagramInPlace(
		serverScratch,
		h.clientEndpoint,
		wire,
	)
	if err != nil {
		t.Fatalf("server activation transport: %v", err)
	}
	if inbound.Kind != dataplane.InboundKeepalive || inbound.KeepaliveID != 0 {
		t.Fatalf("activation inbound=%+v, want KEEPALIVE id 0", inbound)
	}
	if !deliverACK {
		return
	}
	if len(response) == 0 || destination != h.clientEndpoint {
		t.Fatalf("activation ACK len=%d destination=%v", len(response), destination)
	}
	if len(response) < dataplane.MinGeneratedEstablishmentWirePacketSize || len(response) > len(wire) {
		t.Fatalf("activation ACK size=%d, want [%d, %d]", len(response), dataplane.MinGeneratedEstablishmentWirePacketSize, len(wire))
	}
	clientScratch, err = h.clientCore.NewDataScratch()
	if err != nil {
		t.Fatal(err)
	}
	ack, _, _, err := h.clientCore.HandleNetworkDatagramInPlace(
		clientScratch,
		h.serverEndpoint,
		response,
	)
	if err != nil {
		t.Fatalf("client activation ACK: %v", err)
	}
	if ack.Kind != dataplane.InboundACK || ack.KeepaliveID != 0 {
		t.Fatalf("activation ACK=%+v, want keepalive id 0", ack)
	}
}

func (h *noiseLifecycleHarness) establishCurrent(t *testing.T, sessionID uint64) {
	t.Helper()
	init := h.waitInit(t)
	response := h.processInit(t, init)
	h.deliverResponse(t, response)
	if current := h.clientCore.Session(); current == nil || current.ID() != sessionID {
		t.Fatalf("client current=%v, want %#x", current, sessionID)
	}
	h.deliverTransport(t, h.waitTransport(t), true)
	if current := h.serverCore.CurrentSession(h.clientIP); current == nil || current.ID() != sessionID {
		t.Fatalf("server current=%v, want %#x", current, sessionID)
	}
}

func (h *noiseLifecycleHarness) assertClientToServerData(t *testing.T, payload string) {
	t.Helper()
	inner := lifecycleIPv4Packet(h.clientIP, h.serverIP, []byte(payload))
	clientScratch, err := h.clientCore.NewDataScratch()
	if err != nil {
		t.Fatal(err)
	}
	wire, destination, err := h.clientCore.HandleInnerPacketTo(
		clientScratch,
		make([]byte, 0, len(inner)+dataplane.MaxDataExpansion),
		inner,
	)
	if err != nil {
		t.Fatalf("client DATA admission/seal: %v", err)
	}
	if destination != h.serverEndpoint {
		t.Fatalf("client DATA destination=%v, want %v", destination, h.serverEndpoint)
	}
	serverScratch, err := h.serverCore.NewDataScratch()
	if err != nil {
		t.Fatal(err)
	}
	inbound, _, _, err := h.serverCore.HandleNetworkDatagramInPlace(serverScratch, h.clientEndpoint, wire)
	if err != nil {
		t.Fatalf("server DATA receive: %v", err)
	}
	if inbound.Kind != dataplane.InboundIPv4 || !bytes.Equal(inbound.IPv4, inner) {
		t.Fatalf("server DATA inbound=%+v, want original IPv4 packet", inbound)
	}
}

func (h *noiseLifecycleHarness) assertServerToClientData(t *testing.T, payload string) {
	t.Helper()
	inner := lifecycleIPv4Packet(h.serverIP, h.clientIP, []byte(payload))
	serverScratch, err := h.serverCore.NewDataScratch()
	if err != nil {
		t.Fatal(err)
	}
	wire, destination, err := h.serverCore.HandleInnerPacketTo(
		serverScratch,
		make([]byte, 0, len(inner)+dataplane.MaxDataExpansion),
		inner,
	)
	if err != nil {
		t.Fatalf("server DATA admission/seal: %v", err)
	}
	if destination != h.clientEndpoint {
		t.Fatalf("server DATA destination=%v, want %v", destination, h.clientEndpoint)
	}
	clientScratch, err := h.clientCore.NewDataScratch()
	if err != nil {
		t.Fatal(err)
	}
	inbound, _, _, err := h.clientCore.HandleNetworkDatagramInPlace(clientScratch, h.serverEndpoint, wire)
	if err != nil {
		t.Fatalf("client DATA receive: %v", err)
	}
	if inbound.Kind != dataplane.InboundIPv4 || !bytes.Equal(inbound.IPv4, inner) {
		t.Fatalf("client DATA inbound=%+v, want original IPv4 packet", inbound)
	}
}

func lifecycleIPv4Packet(source, destination netip.Addr, payload []byte) []byte {
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

type lifecycleClientExchange struct {
	id      uint64
	entropy byte
}

func clientExchange(id uint64, entropy byte) lifecycleClientExchange {
	return lifecycleClientExchange{id: id, entropy: entropy}
}

func lifecycleClientRandom(exchanges ...lifecycleClientExchange) []byte {
	var out []byte
	for _, exchange := range exchanges {
		out = append(out, clientRandomBytes(exchange.id, exchange.entropy)...)
	}
	return out
}

type lifecycleServerExchange struct {
	sessionID uint64
	entropy   byte
}

func serverExchange(sessionID uint64, entropy byte) lifecycleServerExchange {
	return lifecycleServerExchange{sessionID: sessionID, entropy: entropy}
}

func lifecycleServerRandom(exchanges ...lifecycleServerExchange) []byte {
	var out []byte
	for _, exchange := range exchanges {
		var raw [8]byte
		binary.LittleEndian.PutUint64(raw[:], exchange.sessionID)
		out = append(out, raw[:]...)
		out = append(out, testEntropy(exchange.entropy)...)
		out = append(out, generatedResponseRandomBytes()...)
	}
	return out
}

func parseLifecycleInit(routeKey [32]byte, packet []byte) (wirePacket, error) {
	scratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		return wirePacket{}, err
	}
	route, err := dataplane.DecodeRoute(scratch, packet)
	if err != nil {
		return wirePacket{}, err
	}
	return parseInitPacket(scratch, route, true, packet)
}
