package noisehandshake

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	coreclient "github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestNoiseClientStartEmitsAuthenticatedIKInit(t *testing.T) {
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
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")

	factory := newNoiseTestClientFactory(t, clientPrivate, serverPublic, endpoint, clientRandomBytes(11, 0x81))
	attempt, update, err := factory.Start(time.Unix(1_700_000_000, 123))
	if err != nil {
		t.Fatal(err)
	}
	if attempt == nil || len(update.Outbound) != 1 || update.Material != nil {
		t.Fatalf("start update attempt=%v outbound=%d material=%v", attempt != nil, len(update.Outbound), update.Material != nil)
	}
	if update.Outbound[0].Destination != endpoint {
		t.Fatalf("destination=%v, want %v", update.Outbound[0].Destination, endpoint)
	}
	wire, err := parseNoiseTestInit(update.Outbound[0].Packet)
	if err != nil {
		t.Fatalf("parse INIT: %v", err)
	}
	if wire.exchangeID != 11 {
		t.Fatalf("exchange id=%d, want 11", wire.exchangeID)
	}

	responder, err := newResponderHandshake(serverPrivate, wire.exchangeID, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	payload, _, _, err := responder.ReadMessage(nil, wire.message)
	if err != nil {
		t.Fatalf("responder ReadMessage: %v", err)
	}
	freshness, err := ParseFreshness(payload)
	if err != nil {
		t.Fatalf("freshness payload: %v", err)
	}
	if freshness != testFreshness(1_700_000_000, 123) {
		t.Fatalf("freshness=%d", freshness)
	}
	authenticatedClient, err := peerStaticPublicKey(responder)
	if err != nil {
		t.Fatal(err)
	}
	if authenticatedClient != clientPublic {
		t.Fatalf("authenticated client=%x want=%x", authenticatedClient, clientPublic)
	}
}

func TestNoiseClientRetryCreatesCompletelyNewExchange(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")
	random := append(clientRandomBytes(101, 0x81), clientRandomBytes(202, 0xa1)...)
	factory := newNoiseTestClientFactory(t, clientPrivate, serverPublic, endpoint, random)
	now := time.Unix(1_700_000_000, 900)

	attempt, first, err := factory.Start(now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := attempt.Retry(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	firstWire, _ := parseNoiseTestInit(first.Outbound[0].Packet)
	secondWire, _ := parseNoiseTestInit(second.Outbound[0].Packet)
	if firstWire.exchangeID != 101 || secondWire.exchangeID != 202 || firstWire.exchangeID == secondWire.exchangeID {
		t.Fatalf("exchange ids first=%d second=%d", firstWire.exchangeID, secondWire.exchangeID)
	}
	if bytes.Equal(firstWire.message[:32], secondWire.message[:32]) {
		t.Fatal("retry reused Noise ephemeral public key")
	}
	firstFreshness := readNoiseTestInitFreshness(t, serverPrivate, first.Outbound[0].Packet)
	secondFreshness := readNoiseTestInitFreshness(t, serverPrivate, second.Outbound[0].Packet)
	if secondFreshness <= firstFreshness {
		t.Fatalf("retry freshness did not advance: first=%x second=%x", firstFreshness, secondFreshness)
	}
}

func TestNoiseClientFreshnessContinuesAcrossFactoryAttempts(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")
	random := append(clientRandomBytes(1, 0x81), clientRandomBytes(2, 0xa1)...)
	factory := newNoiseTestClientFactory(t, clientPrivate, serverPublic, endpoint, random)
	now := time.Unix(1_700_000_000, 500)

	_, first, err := factory.Start(now)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := factory.Start(now)
	if err != nil {
		t.Fatal(err)
	}
	f1 := readNoiseTestInitFreshness(t, serverPrivate, first.Outbound[0].Packet)
	f2 := readNoiseTestInitFreshness(t, serverPrivate, second.Outbound[0].Packet)
	if f2 <= f1 {
		t.Fatalf("factory freshness reset between attempts: first=%x second=%x", f1, f2)
	}
}

func TestNoiseClientDelayedOldResponseDuringRetryIsConsumed(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")
	random := append(clientRandomBytes(10, 0x81), clientRandomBytes(20, 0xa1)...)
	factory := newNoiseTestClientFactory(t, clientPrivate, serverPublic, endpoint, random)

	attempt, h1, err := factory.Start(time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	response1 := makeNoiseTestResponseForInit(t, serverPrivate, h1.Outbound[0].Packet, 111, 0x41, nil)
	h2, err := attempt.Retry(time.Unix(101, 0))
	if err != nil {
		t.Fatal(err)
	}
	response2 := makeNoiseTestResponseForInit(t, serverPrivate, h2.Outbound[0].Packet, 222, 0x61, nil)

	handled, update, err := handleNoiseTestAttempt(attempt, endpoint, response1)
	if err != nil || !handled || update.Material != nil {
		t.Fatalf("old response handled=%v material=%v err=%v", handled, update.Material != nil, err)
	}
	handled, update, err = handleNoiseTestAttempt(attempt, endpoint, response2)
	if err != nil || !handled || update.Material == nil {
		t.Fatalf("current response handled=%v material=%v err=%v", handled, update.Material != nil, err)
	}
	if update.Material.SessionID != 222 {
		t.Fatalf("session id=%d, want 222", update.Material.SessionID)
	}
}

func TestNoiseClientAcceptsAuthenticatedResponseFromDifferentSource(t *testing.T) {
	attempt, _, response := makeNoiseClientAttemptAndResponse(t, 333)
	otherSource := netip.MustParseAddrPort("198.51.100.99:51820")

	handled, update, err := handleNoiseTestAttempt(attempt, otherSource, response)
	if err != nil || !handled || update.Material == nil || update.Material.SessionID != 333 {
		t.Fatalf("response handled=%v material=%v err=%v", handled, update.Material, err)
	}
}

func TestNoiseClientAuthenticatedZeroSessionIDIsSilent(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")
	factory := newNoiseTestClientFactory(t, clientPrivate, serverPublic, endpoint, clientRandomBytes(7, 0x81))
	attempt, init, err := factory.Start(time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}

	zeroPayload := make([]byte, responsePayloadSize)
	zeroResponse := makeNoiseTestResponseForInit(t, serverPrivate, init.Outbound[0].Packet, 0, 0x41, zeroPayload)
	handled, update, err := handleNoiseTestAttempt(attempt, endpoint, zeroResponse)
	if err != nil || !handled || update.Material != nil {
		t.Fatalf("zero session response handled=%v material=%v err=%v", handled, update.Material != nil, err)
	}
}

func TestNoiseClientMalformedOwnedResponseIsSilent(t *testing.T) {
	attempt, endpoint, response := makeNoiseClientAttemptAndResponse(t, 666)

	malformed := append([]byte(nil), response...)
	malformed[len(malformed)-17] ^= 0x40
	handled, update, err := handleNoiseTestAttempt(attempt, endpoint, malformed)
	if err != nil || !handled || update.Material != nil {
		t.Fatalf("malformed owned response handled=%v material=%v err=%v", handled, update.Material != nil, err)
	}

	nonNoise := []byte("encrypted dataplane candidate")
	handled, _, err = handleNoiseTestAttempt(attempt, endpoint, nonNoise)
	if err != nil || handled {
		t.Fatalf("non-Noise handled=%v err=%v", handled, err)
	}
}

func TestNoiseClientExchangeIDSkipsZeroAndRejectsPermanentZeroRNG(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")

	var zero [8]byte
	random := append([]byte(nil), zero[:]...)
	random = append(random, clientRandomBytes(77, 0x81)...)
	factory := newNoiseTestClientFactory(t, clientPrivate, serverPublic, endpoint, random)
	_, update, err := factory.Start(time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := parseNoiseTestInit(update.Outbound[0].Packet)
	if err != nil {
		t.Fatal(err)
	}
	if wire.exchangeID != 77 {
		t.Fatalf("exchange id=%d, want 77 after skipping zero", wire.exchangeID)
	}

	factory = newNoiseTestClientFactory(t, clientPrivate, serverPublic, endpoint, make([]byte, maxZeroExchangeIDAttempts*8))
	if _, _, err := factory.Start(time.Unix(100, 0)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("permanent zero RNG error=%v, want ErrInvalidState", err)
	}
}

func TestNoiseClientStartAndRetryRNGFailuresAreLocalErrors(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")

	factory := newNoiseTestClientFactoryWithReader(t, clientPrivate, serverPublic, endpoint, errorReader{err: io.ErrUnexpectedEOF})
	if _, _, err := factory.Start(time.Unix(100, 0)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Start RNG error=%v, want io.ErrUnexpectedEOF", err)
	}

	rng := &switchableReader{r: bytes.NewReader(clientRandomBytes(1, 0x81))}
	factory = newNoiseTestClientFactoryWithReader(t, clientPrivate, serverPublic, endpoint, rng)
	attempt, _, err := factory.Start(time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	rng.Fail()
	if _, err := attempt.Retry(time.Unix(101, 0)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Retry RNG error=%v, want io.ErrUnexpectedEOF", err)
	}
}

func TestNoiseClientRejectsInvalidConfiguration(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)

	_, err := NewClient(ClientConfig{
		ServerEndpoint:   netip.MustParseAddrPort("[2001:db8::1]:51820"),
		StaticPrivateKey: clientPrivate,
		ServerPublicKey:  serverPublic,
	})
	if err == nil {
		t.Fatal("NewClient accepted IPv6 server endpoint")
	}

	_, err = NewClient(ClientConfig{
		ServerEndpoint:   netip.MustParseAddrPort("192.0.2.10:51820"),
		StaticPrivateKey: PrivateKey{},
		ServerPublicKey:  serverPublic,
	})
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("zero client private key error=%v, want ErrInvalidKey", err)
	}

	_, err = NewClient(ClientConfig{
		ServerEndpoint:   netip.MustParseAddrPort("192.0.2.10:51820"),
		StaticPrivateKey: clientPrivate,
		ServerPublicKey:  PublicKey{},
	})
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("zero server public key error=%v, want ErrInvalidKey", err)
	}
}

func TestNoiseClientIntegratesWithSessionController(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")
	tunnelIPv4 := netip.MustParseAddr("10.66.0.2")

	core, err := coreclient.New(coreclient.Config{
		TunnelIPv4:         tunnelIPv4,
		ServerEndpoint:     endpoint,
		MaxInnerPacketSize: 1380,
		Lifecycle: coreclient.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Session: nil,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	factory := newNoiseTestClientFactory(t, clientPrivate, serverPublic, endpoint, clientRandomBytes(91, 0x81))
	runtime := newNoiseClientControllerRuntime()
	controller, err := coreclient.NewSessionController(core, runtime, factory, coreclient.SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: 5 * time.Second,
		EstablishmentRetryMax: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSessionController: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- controller.Run(ctx) }()

	var init coreclient.EstablishmentDatagram
	select {
	case init = <-runtime.sent:
	case <-time.After(time.Second):
		t.Fatal("controller did not emit Noise INIT")
	}
	if init.Destination != endpoint {
		t.Fatalf("INIT destination=%v, want %v", init.Destination, endpoint)
	}
	response := makeNoiseTestResponseForInit(t, serverPrivate, init.Packet, 0x1122334455667788, 0x41, nil)
	if handled, err := handleNoiseTestController(controller, endpoint, response); err != nil || !handled {
		t.Fatalf("HandleDatagram RESPONSE handled=%v err=%v", handled, err)
	}

	if core.Session() == nil || core.Session().ID() != 0x1122334455667788 {
		t.Fatalf("current session=%v, want established Noise generation", core.Session())
	}
	select {
	case keepalive := <-runtime.transport:
		if keepalive == nil || keepalive.Session() != core.Session() || keepalive.Destination() != endpoint {
			t.Fatalf("activation keepalive does not use installed session/destination")
		}
	case <-time.After(time.Second):
		t.Fatal("controller did not submit activation KEEPALIVE")
	}

	close(runtime.done)
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("controller Run: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("controller did not stop after runtime Done")
	}
}

func TestNoiseClientClassifierOwnsHiddenRouteNamespaceForLifetime(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	factory := newNoiseTestClientFactory(t, clientPrivate, serverPublic, netip.MustParseAddrPort("192.0.2.10:51820"), clientRandomBytes(1, 0x81))

	packet := make([]byte, ResponseMinPacketSize)
	if !factory.IsEstablishmentDatagram(dataplane.Route{SessionID: 0, Sequence: 1}, true, packet) {
		t.Fatal("reserved route namespace was not classified as establishment")
	}
	if factory.IsEstablishmentDatagram(dataplane.Route{SessionID: 7, Sequence: 1}, true, packet) {
		t.Fatal("ordinary datagram classified as establishment")
	}
	if factory.IsEstablishmentDatagram(dataplane.Route{}, false, packet) {
		t.Fatal("undecodable route classified as establishment")
	}
}

type noiseClientControllerRuntime struct {
	ready     chan struct{}
	done      chan struct{}
	sent      chan coreclient.EstablishmentDatagram
	transport chan *coreclient.OutboundOperation
}

func newNoiseClientControllerRuntime() *noiseClientControllerRuntime {
	ready := make(chan struct{})
	close(ready)
	return &noiseClientControllerRuntime{
		ready:     ready,
		done:      make(chan struct{}),
		sent:      make(chan coreclient.EstablishmentDatagram, 4),
		transport: make(chan *coreclient.OutboundOperation, 4),
	}
}

func (r *noiseClientControllerRuntime) SendProtocolDatagram(packet []byte, destination netip.AddrPort) error {
	r.sent <- coreclient.EstablishmentDatagram{
		Packet:      append([]byte(nil), packet...),
		Destination: destination,
	}
	return nil
}

func (r *noiseClientControllerRuntime) SubmitProtocolTransport(op *coreclient.OutboundOperation) error {
	r.transport <- op
	return nil
}

func (r *noiseClientControllerRuntime) Ready() <-chan struct{} { return r.ready }
func (r *noiseClientControllerRuntime) Done() <-chan struct{}  { return r.done }

func makeNoiseClientAttemptAndResponse(t *testing.T, sessionID uint64) (coreclient.EstablishmentAttempt, netip.AddrPort, []byte) {
	t.Helper()
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, _ := PublicKeyFromPrivate(serverPrivate)
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")
	factory := newNoiseTestClientFactory(t, clientPrivate, serverPublic, endpoint, clientRandomBytes(1, 0x81))
	attempt, init, err := factory.Start(time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	response := makeNoiseTestResponseForInit(t, serverPrivate, init.Outbound[0].Packet, sessionID, 0x41, nil)
	return attempt, endpoint, response
}

func newNoiseTestClientFactory(
	t *testing.T,
	clientPrivate PrivateKey,
	serverPublic PublicKey,
	endpoint netip.AddrPort,
	random []byte,
) *Client {
	t.Helper()
	return newNoiseTestClientFactoryWithReader(t, clientPrivate, serverPublic, endpoint, bytes.NewReader(random))
}

func newNoiseTestClientFactoryWithReader(
	t *testing.T,
	clientPrivate PrivateKey,
	serverPublic PublicKey,
	endpoint netip.AddrPort,
	random io.Reader,
) *Client {
	t.Helper()
	factory, err := NewClient(ClientConfig{
		ServerEndpoint:   endpoint,
		RouteKey:         [32]byte{},
		StaticPrivateKey: clientPrivate,
		ServerPublicKey:  serverPublic,
		Random:           random,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return factory
}

func clientRandomBytes(exchangeID uint64, ephemeralStart byte) []byte {
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], exchangeID)
	out := append([]byte(nil), raw[:]...)
	out = append(out, testEntropy(ephemeralStart)...)
	return append(out, generatedInitRandomBytes()...)
}

func readNoiseTestInitFreshness(t *testing.T, serverPrivate PrivateKey, packet []byte) Freshness {
	t.Helper()
	wire, err := parseNoiseTestInit(packet)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newResponderHandshake(serverPrivate, wire.exchangeID, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	payload, _, _, err := server.ReadMessage(nil, wire.message)
	if err != nil {
		t.Fatal(err)
	}
	freshness, err := ParseFreshness(payload)
	if err != nil {
		t.Fatal(err)
	}
	return freshness
}

func makeNoiseTestResponseForInit(
	t *testing.T,
	serverPrivate PrivateKey,
	initPacket []byte,
	sessionID uint64,
	entropyStart byte,
	payloadOverride []byte,
) []byte {
	t.Helper()
	wire, err := parseNoiseTestInit(initPacket)
	if err != nil {
		t.Fatalf("parse INIT: %v", err)
	}
	server, err := newResponderHandshake(serverPrivate, wire.exchangeID, bytes.NewReader(testEntropy(entropyStart)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := server.ReadMessage(nil, wire.message); err != nil {
		t.Fatalf("server ReadMessage: %v", err)
	}

	payload := payloadOverride
	if payload == nil {
		var encoded [responsePayloadSize]byte
		binary.LittleEndian.PutUint64(encoded[:], sessionID)
		payload = encoded[:]
	}
	message, cs1, cs2, err := server.WriteMessage(nil, payload)
	if err != nil {
		t.Fatalf("server WriteMessage: %v", err)
	}
	if cs1 == nil || cs2 == nil {
		t.Fatal("server IK response did not complete handshake")
	}
	scratch, err := dataplane.NewDataScratch([32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	paddingLen := len(initPacket) - dataplane.RouteSize - responseNoiseMessageSize
	packet, err := appendResponsePacket(
		make([]byte, 0, len(initPacket)),
		scratch,
		bytes.NewReader(make([]byte, paddingLen)),
		wire.exchangeID,
		message,
		len(initPacket),
	)
	if err != nil {
		t.Fatalf("append RESPONSE: %v", err)
	}
	return packet
}

func parseNoiseTestInit(packet []byte) (wirePacket, error) {
	scratch, err := dataplane.NewDataScratch([32]byte{})
	if err != nil {
		return wirePacket{}, err
	}
	route, err := dataplane.DecodeRoute(scratch, packet)
	if err != nil {
		return wirePacket{}, err
	}
	return parseInitPacket(scratch, route, true, packet)
}

func decodeNoiseTestRoute(packet []byte) (dataplane.Route, bool, error) {
	scratch, err := dataplane.NewDataScratch([32]byte{})
	if err != nil {
		return dataplane.Route{}, false, err
	}
	route, err := dataplane.DecodeRoute(scratch, packet)
	if err != nil {
		return dataplane.Route{}, false, nil
	}
	return route, true, nil
}

func handleNoiseTestAttempt(
	attempt coreclient.EstablishmentAttempt,
	source netip.AddrPort,
	packet []byte,
) (bool, coreclient.EstablishmentUpdate, error) {
	route, routeDecoded, err := decodeNoiseTestRoute(packet)
	if err != nil {
		return false, coreclient.EstablishmentUpdate{}, err
	}
	return attempt.HandleDatagram(time.Time{}, source, route, routeDecoded, packet)
}

func handleNoiseTestController(
	controller *coreclient.SessionController,
	source netip.AddrPort,
	packet []byte,
) (bool, error) {
	route, routeDecoded, err := decodeNoiseTestRoute(packet)
	if err != nil {
		return false, err
	}
	return controller.HandleDatagram(source, route, routeDecoded, packet)
}
