package client

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func newClientOperationCore(
	t *testing.T,
	current *dataplane.Session,
) (*Core, [32]byte, netip.AddrPort) {
	t.Helper()
	routeKey, _, _ := testKeys()
	serverEndpoint := netip.MustParseAddrPort("198.51.100.10:51820")
	core, err := New(Config{
		RouteKey:           routeKey,
		TunnelIPv4:         netip.MustParseAddr("10.66.0.2"),
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Session:            current,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return core, routeKey, serverEndpoint
}

func TestClientOutboundOperationPinsSessionAcrossRotation(t *testing.T) {
	clientA, serverA := newClientLifecycleSessionPair(t, 0x9101, 0x11, 7)
	clientB, _ := newClientLifecycleSessionPair(t, 0x9102, 0x22, 0)
	core, routeKey, serverEndpoint := newClientOperationCore(t, clientA)

	t0 := time.Unix(1_700_300_000, 0)
	core.now = func() time.Time { return t0 }
	inner := testIPv4Packet(
		t,
		core.TunnelIPv4(),
		netip.MustParseAddr("203.0.113.9"),
		[]byte("pinned before rotation"),
	)

	op, err := core.AdmitInnerPacket(inner, len(inner)+dataplane.MaxDataExpansion)
	if err != nil {
		t.Fatalf("AdmitInnerPacket: %v", err)
	}
	if op.Session() != clientA || op.Sequence() != 7 {
		t.Fatalf("admission did not pin A/7: session=%p sequence=%d", op.Session(), op.Sequence())
	}

	if _, err := core.InstallInitiatorSession(clientB); err != nil {
		t.Fatalf("InstallInitiatorSession(B): %v", err)
	}
	if core.Session() != clientB {
		t.Fatal("B is not current after install")
	}

	scratch, err := core.NewDataScratch()
	if err != nil {
		t.Fatalf("NewDataScratch: %v", err)
	}
	wire, err := op.SealTo(scratch, make([]byte, 0, op.MaxWireSize()))
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	if op.Destination() != serverEndpoint {
		t.Fatalf("destination=%v, want %v", op.Destination(), serverEndpoint)
	}

	decodeScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("NewDataScratch(server): %v", err)
	}
	route, err := dataplane.DecodeRoute(decodeScratch, wire)
	if err != nil {
		t.Fatalf("DecodeRoute: %v", err)
	}
	if route.SessionID != clientA.ID() || route.Sequence != 7 {
		t.Fatalf("wire route=(%x,%d), want A/%d", route.SessionID, route.Sequence, 7)
	}
	plaintext, err := serverA.AuthenticateInPlace(decodeScratch, wire, route.Sequence)
	if err != nil {
		t.Fatalf("AuthenticateInPlace(A): %v", err)
	}
	got, _, err := dataplane.ParseDataIPv4(plaintext, dataplane.ReferenceTunnelMTU)
	if err != nil {
		t.Fatalf("ParseDataIPv4: %v", err)
	}
	if !bytes.Equal(got, inner) {
		t.Fatal("sealed operation changed payload across rotation")
	}
}

func TestClientAdmissionRejectsLocalErrorsBeforeSequenceReservation(t *testing.T) {
	clientA, _ := newClientLifecycleSessionPair(t, 0x9201, 0x11, 41)
	core, _, _ := newClientOperationCore(t, clientA)

	inner := testIPv4Packet(
		t,
		core.TunnelIPv4(),
		netip.MustParseAddr("203.0.113.10"),
		nil,
	)
	if _, err := core.AdmitInnerPacket(inner, len(inner)); !errors.Is(err, dataplane.ErrBufferTooSmall) {
		t.Fatalf("small DATA buffer error=%v, want ErrBufferTooSmall", err)
	}
	if _, err := core.AdmitKeepalive(1, dataplane.MinControlWirePacketSize); !errors.Is(err, dataplane.ErrBufferTooSmall) {
		t.Fatalf("small KEEPALIVE buffer error=%v, want ErrBufferTooSmall", err)
	}
	if got := clientA.TxSequence(); got != 41 {
		t.Fatalf("local admission error consumed sequence: got %d want 41", got)
	}
}

func TestClientUnknownSessionRejectedAtAdmission(t *testing.T) {
	clientA, serverA := newClientLifecycleSessionPair(t, 0x9301, 0x11, 0)
	core, routeKey, endpoint := newClientOperationCore(t, clientA)
	_, foreignServer := newClientLifecycleSessionPair(t, 0x9302, 0x22, 0)
	_ = serverA

	txScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("NewDataScratch: %v", err)
	}
	inner := testIPv4Packet(t, netip.MustParseAddr("10.66.0.1"), core.TunnelIPv4(), nil)
	wire, _, err := foreignServer.SealDataTo(
		txScratch,
		make([]byte, 0, len(inner)+dataplane.MaxDataExpansion),
		inner,
	)
	if err != nil {
		t.Fatalf("SealDataTo: %v", err)
	}

	rxScratch, _ := core.NewDataScratch()
	if _, err := core.AdmitNetworkDatagram(rxScratch, endpoint, wire); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("error=%v, want ErrUnknownSession", err)
	}
}

func TestClientAdmitNetworkDatagramAtUsesIngressTimestamp(t *testing.T) {
	clientA, serverA := newClientLifecycleSessionPair(t, 0x9303, 0x33, 0)
	core, routeKey, endpoint := newClientOperationCore(t, clientA)

	// The generation was installed by New just before this timestamp and is
	// therefore still valid at receivedAt. Move the Core clock far beyond its
	// hard lifetime to model control-plane/demux work finishing much later.
	receivedAt := time.Now()
	core.now = func() time.Time { return receivedAt.Add(24 * time.Hour) }

	inner := testIPv4Packet(
		t,
		netip.MustParseAddr("10.66.0.1"),
		core.TunnelIPv4(),
		[]byte("captured before demux"),
	)
	txScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("NewDataScratch(TX): %v", err)
	}
	wire, _, err := serverA.SealDataTo(
		txScratch,
		make([]byte, 0, len(inner)+dataplane.MaxDataExpansion),
		inner,
	)
	if err != nil {
		t.Fatalf("SealDataTo: %v", err)
	}

	lateScratch, _ := core.NewDataScratch()
	if _, err := core.AdmitNetworkDatagram(lateScratch, endpoint, wire); !errors.Is(err, ErrSessionNotRXEligible) {
		t.Fatalf("late implicit timestamp error=%v, want ErrSessionNotRXEligible", err)
	}

	ingressScratch, _ := core.NewDataScratch()
	op, err := core.AdmitNetworkDatagramAt(ingressScratch, endpoint, wire, receivedAt)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagramAt(receivedAt): %v", err)
	}
	if op.admission.Session != clientA || !op.admission.ReceivedAt.Equal(receivedAt) {
		t.Fatalf("admission=%+v, want exact A at captured ingress timestamp", op.admission)
	}
}
