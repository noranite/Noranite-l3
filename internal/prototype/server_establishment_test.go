package prototype

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

type testServerEstablishmentIngress struct {
	classify func([]byte) bool
	handle   func(netip.AddrPort, []byte) (bool, []byte, netip.AddrPort, error)
}

func (i testServerEstablishmentIngress) IsEstablishmentDatagram(
	_ dataplane.Route,
	_ bool,
	packet []byte,
) bool {
	return i.classify(packet)
}

func (i testServerEstablishmentIngress) TryHandleEstablishmentDatagramInPlace(
	source netip.AddrPort,
	_ dataplane.Route,
	_ bool,
	packet []byte,
) (bool, []byte, netip.AddrPort, error) {
	return i.handle(source, packet)
}

func TestServerEstablishmentExecutorSaturationDoesNotBlockDataplaneClassification(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var handled atomic.Int32

	ingress := testServerEstablishmentIngress{
		classify: func(packet []byte) bool {
			return len(packet) > 0 && packet[0] == 0xe1
		},
		handle: func(
			source netip.AddrPort,
			packet []byte,
		) (bool, []byte, netip.AddrPort, error) {
			handled.Add(1)
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			return true, nil, netip.AddrPort{}, nil
		},
	}

	var reported atomic.Int32
	executor, err := newServerEstablishmentExecutor(
		ingress,
		64,
		1,
		1,
		func([]byte, netip.AddrPort) error { return nil },
		func(error) { reported.Add(1) },
	)
	if err != nil {
		t.Fatalf("newServerEstablishmentExecutor: %v", err)
	}

	source := netip.MustParseAddrPort("192.0.2.10:40000")
	if owned, accepted := executor.TrySubmit(source, dataplane.Route{}, false, []byte{0xe1, 1}); !owned || !accepted {
		t.Fatalf("first establishment submit=(owned=%v accepted=%v), want true,true", owned, accepted)
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("establishment worker did not start")
	}

	if owned, accepted := executor.TrySubmit(source, dataplane.Route{}, false, []byte{0xe1, 2}); !owned || !accepted {
		t.Fatalf("queued establishment submit=(owned=%v accepted=%v), want true,true", owned, accepted)
	}
	if owned, accepted := executor.TrySubmit(source, dataplane.Route{}, false, []byte{0xe1, 3}); !owned || accepted {
		t.Fatalf("saturated establishment submit=(owned=%v accepted=%v), want true,false", owned, accepted)
	}

	// A slow/saturated establishment provider must not affect classification of
	// ordinary encrypted dataplane traffic. The UDP reader can immediately move
	// on to Core admission when owned=false.
	if owned, accepted := executor.TrySubmit(source, dataplane.Route{}, false, []byte{0x44, 0x55}); owned || accepted {
		t.Fatalf("dataplane submit=(owned=%v accepted=%v), want false,false", owned, accepted)
	}

	close(release)
	executor.CloseAndWait()

	if got := handled.Load(); got != 2 {
		t.Fatalf("handled establishment jobs=%d, want 2", got)
	}
	if got := reported.Load(); got != 0 {
		t.Fatalf("reported errors=%d, want 0", got)
	}
}

func TestServerEstablishmentExecutorCopiesPacketAndKeepsAliasedResponseUntilSend(t *testing.T) {
	entered := make(chan struct{})
	allowRead := make(chan struct{})
	sent := make(chan []byte, 1)

	destination := netip.MustParseAddrPort("192.0.2.20:50000")
	ingress := testServerEstablishmentIngress{
		classify: func(packet []byte) bool { return true },
		handle: func(
			source netip.AddrPort,
			packet []byte,
		) (bool, []byte, netip.AddrPort, error) {
			close(entered)
			<-allowRead
			if len(packet) != 3 || packet[0] != 1 || packet[1] != 2 || packet[2] != 3 {
				t.Errorf("worker observed packet %v, want original [1 2 3]", packet)
			}
			// Deliberately return a response aliasing the executor-owned input.
			packet[0] = 9
			packet[1] = 8
			return true, packet[:2], destination, nil
		},
	}

	executor, err := newServerEstablishmentExecutor(
		ingress,
		16,
		1,
		1,
		func(response []byte, gotDestination netip.AddrPort) error {
			if gotDestination != destination {
				t.Errorf("response destination=%v, want %v", gotDestination, destination)
			}
			sent <- append([]byte(nil), response...)
			return nil
		},
		func(err error) { t.Errorf("unexpected reported error: %v", err) },
	)
	if err != nil {
		t.Fatalf("newServerEstablishmentExecutor: %v", err)
	}

	source := netip.MustParseAddrPort("192.0.2.30:51000")
	packet := []byte{1, 2, 3}
	if owned, accepted := executor.TrySubmit(source, dataplane.Route{}, false, packet); !owned || !accepted {
		t.Fatalf("TrySubmit=(owned=%v accepted=%v), want true,true", owned, accepted)
	}

	<-entered
	packet[0], packet[1], packet[2] = 7, 7, 7
	close(allowRead)

	select {
	case response := <-sent:
		if len(response) != 2 || response[0] != 9 || response[1] != 8 {
			t.Fatalf("sent response=%v, want [9 8]", response)
		}
	case <-time.After(time.Second):
		t.Fatal("response was not sent")
	}

	executor.CloseAndWait()
}

func TestServerEstablishmentExecutorReportsProviderError(t *testing.T) {
	providerErr := errors.New("provider failed")
	reported := make(chan error, 1)
	var sends atomic.Int32

	ingress := testServerEstablishmentIngress{
		classify: func([]byte) bool { return true },
		handle: func(
			netip.AddrPort,
			[]byte,
		) (bool, []byte, netip.AddrPort, error) {
			return true, nil, netip.AddrPort{}, providerErr
		},
	}

	executor, err := newServerEstablishmentExecutor(
		ingress,
		16,
		1,
		1,
		func([]byte, netip.AddrPort) error {
			sends.Add(1)
			return nil
		},
		func(err error) { reported <- err },
	)
	if err != nil {
		t.Fatalf("newServerEstablishmentExecutor: %v", err)
	}

	if owned, accepted := executor.TrySubmit(
		netip.MustParseAddrPort("192.0.2.40:52000"),
		dataplane.Route{},
		false,
		[]byte{1},
	); !owned || !accepted {
		t.Fatalf("TrySubmit=(owned=%v accepted=%v), want true,true", owned, accepted)
	}

	select {
	case err := <-reported:
		if !errors.Is(err, providerErr) {
			t.Fatalf("reported error=%v, want provider error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider error was not reported")
	}

	executor.CloseAndWait()
	if got := sends.Load(); got != 0 {
		t.Fatalf("response sends=%d, want 0", got)
	}
}

func TestServerEstablishmentExecutorReportsClassifierHandlerDisagreement(t *testing.T) {
	reported := make(chan error, 1)
	ingress := testServerEstablishmentIngress{
		classify: func([]byte) bool { return true },
		handle: func(
			netip.AddrPort,
			[]byte,
		) (bool, []byte, netip.AddrPort, error) {
			return false, nil, netip.AddrPort{}, nil
		},
	}

	executor, err := newServerEstablishmentExecutor(
		ingress,
		16,
		1,
		1,
		func([]byte, netip.AddrPort) error { return nil },
		func(err error) { reported <- err },
	)
	if err != nil {
		t.Fatalf("newServerEstablishmentExecutor: %v", err)
	}

	if owned, accepted := executor.TrySubmit(
		netip.MustParseAddrPort("192.0.2.50:53000"),
		dataplane.Route{},
		false,
		[]byte{1},
	); !owned || !accepted {
		t.Fatalf("TrySubmit=(owned=%v accepted=%v), want true,true", owned, accepted)
	}

	select {
	case err := <-reported:
		if err == nil {
			t.Fatal("reported nil error")
		}
	case <-time.After(time.Second):
		t.Fatal("classifier/handler disagreement was not reported")
	}

	executor.CloseAndWait()
}

func TestServerEstablishmentExecutorReportsSendError(t *testing.T) {
	sendErr := errors.New("send failed")
	reported := make(chan error, 1)
	destination := netip.MustParseAddrPort("192.0.2.60:54000")

	ingress := testServerEstablishmentIngress{
		classify: func([]byte) bool { return true },
		handle: func(
			netip.AddrPort,
			[]byte,
		) (bool, []byte, netip.AddrPort, error) {
			return true, []byte{4, 5, 6}, destination, nil
		},
	}

	executor, err := newServerEstablishmentExecutor(
		ingress,
		16,
		1,
		1,
		func([]byte, netip.AddrPort) error { return sendErr },
		func(err error) { reported <- err },
	)
	if err != nil {
		t.Fatalf("newServerEstablishmentExecutor: %v", err)
	}

	if owned, accepted := executor.TrySubmit(
		netip.MustParseAddrPort("192.0.2.70:55000"),
		dataplane.Route{},
		false,
		[]byte{1},
	); !owned || !accepted {
		t.Fatalf("TrySubmit=(owned=%v accepted=%v), want true,true", owned, accepted)
	}

	select {
	case err := <-reported:
		if !errors.Is(err, sendErr) {
			t.Fatalf("reported error=%v, want send error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("send error was not reported")
	}

	executor.CloseAndWait()
}
