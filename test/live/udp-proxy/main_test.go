package main

import (
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func establishmentPacket(t *testing.T, routeKey [32]byte, exchangeID uint64) []byte {
	t.Helper()
	scratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, dataplane.RouteSize+64)
	if err := dataplane.WriteRoute(scratch, packet, dataplane.Route{SessionID: 0, Sequence: exchangeID}); err != nil {
		t.Fatal(err)
	}
	return packet
}

func transportPacket(t *testing.T, sessionID uint64, routeKey [32]byte, sequence uint64) []byte {
	t.Helper()
	var key [32]byte
	key[0] = 0x42
	session, err := dataplane.NewSession(sessionID, key, key, sequence)
	if err != nil {
		t.Fatal(err)
	}
	scratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, _, err := session.SealDataTo(
		scratch,
		make([]byte, 0, 128),
		[]byte{0x45},
	)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func bootstrapSession(t *testing.T, state *faultState, routeKey [32]byte, sessionID uint64) {
	t.Helper()
	if forward, _ := state.handleClientPacket(establishmentPacket(t, routeKey, 1)); !forward {
		t.Fatal("bootstrap INIT was dropped")
	}
	if forward, _ := state.handleServerPacket(establishmentPacket(t, routeKey, 1)); !forward {
		t.Fatal("bootstrap RESPONSE was dropped")
	}
	packet := transportPacket(t, sessionID, routeKey, 1)
	if forward, _ := state.handleClientPacket(packet); !forward {
		t.Fatal("bootstrap transport was dropped")
	}
}

func TestDropTargetResponseOnly(t *testing.T) {
	var routeKey [32]byte
	state, err := newFaultState(modeDropResponse, 2, routeKey)
	if err != nil {
		t.Fatal(err)
	}

	if forward, _ := state.handleServerPacket(establishmentPacket(t, routeKey, 1)); !forward {
		t.Fatal("bootstrap RESPONSE was dropped")
	}
	if forward, _ := state.handleServerPacket(establishmentPacket(t, routeKey, 2)); forward {
		t.Fatal("target RESPONSE was forwarded")
	}
	if forward, _ := state.handleServerPacket(establishmentPacket(t, routeKey, 3)); !forward {
		t.Fatal("post-target RESPONSE was dropped")
	}
}

func TestDropResponsesFromTarget(t *testing.T) {
	var routeKey [32]byte
	state, err := newFaultState(modeDropResponsesFromTarget, 2, routeKey)
	if err != nil {
		t.Fatal(err)
	}

	if forward, _ := state.handleServerPacket(establishmentPacket(t, routeKey, 1)); !forward {
		t.Fatal("bootstrap RESPONSE was dropped")
	}
	for ordinal := 2; ordinal <= 4; ordinal++ {
		if forward, _ := state.handleServerPacket(establishmentPacket(t, routeKey, uint64(ordinal))); forward {
			t.Fatalf("RESPONSE ordinal %d was forwarded", ordinal)
		}
	}
}

func TestDropFirstTransportAfterTargetResponse(t *testing.T) {
	var routeKey [32]byte
	routeKey[0] = 0x21
	state, err := newFaultState(modeDropFirstTransportAfterResponse, 2, routeKey)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapSession(t, state, routeKey, 0x1111)

	state.handleClientPacket(establishmentPacket(t, routeKey, 2))
	state.handleServerPacket(establishmentPacket(t, routeKey, 2))
	transport := transportPacket(t, 0x2222, routeKey, 1)
	if forward, _ := state.handleClientPacket(transport); forward {
		t.Fatal("first transport packet after target RESPONSE was forwarded")
	}
	if state.sessionByResponse[2] != 0x2222 {
		t.Fatalf("target session=%#x, want %#x", state.sessionByResponse[2], uint64(0x2222))
	}
	if forward, _ := state.handleClientPacket(transportPacket(t, 0x2222, routeKey, 2)); !forward {
		t.Fatal("second transport packet after target RESPONSE was dropped")
	}
}

func TestBlockTransportUntilNextResponse(t *testing.T) {
	var routeKey [32]byte
	routeKey[0] = 0x31
	state, err := newFaultState(modeBlockTransportUntilNextResponse, 2, routeKey)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapSession(t, state, routeKey, 0x1111)

	state.handleServerPacket(establishmentPacket(t, routeKey, 2))
	if forward, _ := state.handleClientPacket(transportPacket(t, 0x2222, routeKey, 1)); forward {
		t.Fatal("transport was forwarded while block was active")
	}
	if forward, _ := state.handleClientPacket(establishmentPacket(t, routeKey, 3)); !forward {
		t.Fatal("Noise INIT was blocked with transport")
	}

	state.handleServerPacket(establishmentPacket(t, routeKey, 3))
	if forward, _ := state.handleClientPacket(transportPacket(t, 0x3333, routeKey, 1)); !forward {
		t.Fatal("transport remained blocked after next RESPONSE")
	}
	if state.blockedTransportDrops != 1 {
		t.Fatalf("blocked drops=%d, want 1", state.blockedTransportDrops)
	}
}

func TestDelayOldGenerationSplitsEarlyAndLatePackets(t *testing.T) {
	var routeKey [32]byte
	routeKey[0] = 0x91
	state, err := newFaultState(modeDelayOldGeneration, 2, routeKey)
	if err != nil {
		t.Fatal(err)
	}
	const sessionA = uint64(0x1111)
	bootstrapSession(t, state, routeKey, sessionA)

	state.handleClientPacket(establishmentPacket(t, routeKey, 2))
	if !state.oldDelayArmed || state.oldSessionID != sessionA {
		t.Fatalf("old generation not armed: armed=%v session=%#x", state.oldDelayArmed, state.oldSessionID)
	}
	forward, _ := state.handleServerPacket(establishmentPacket(t, routeKey, 2))
	action, _ := state.decorateServerPacket(establishmentPacket(t, routeKey, 2), forward)
	if action.delay != rekeyResponseDelay {
		t.Fatalf("RESPONSE delay=%s, want %s", action.delay, rekeyResponseDelay)
	}

	for i := 1; i <= 4; i++ {
		packet := transportPacket(t, sessionA, routeKey, uint64(i+1))
		forward, _ := state.handleClientPacket(packet)
		action, _ := state.decorateClientPacket(packet, forward)
		want := oldGenerationEarlyDelay
		if i > 2 {
			want = oldGenerationLateDelay
		}
		if action.delay != want {
			t.Fatalf("old packet %d delay=%s, want %s", i, action.delay, want)
		}
	}

	packet := transportPacket(t, sessionA, routeKey, 9)
	forward, _ = state.handleClientPacket(packet)
	action, _ = state.decorateClientPacket(packet, forward)
	if action.delay != 0 {
		t.Fatalf("fifth old packet delay=%s, want immediate forwarding", action.delay)
	}
}

func TestDuplicateReplayLearnsNoiseSessionAndTargetsFirstTwoPackets(t *testing.T) {
	var routeKey [32]byte
	routeKey[0] = 0x37
	state, err := newFaultState(modeDuplicateReplay, 2, routeKey)
	if err != nil {
		t.Fatal(err)
	}
	const sessionA = uint64(0x1111)
	const sessionB = uint64(0x2222)
	bootstrapSession(t, state, routeKey, sessionA)
	state.handleServerPacket(establishmentPacket(t, routeKey, 2))

	for i := 1; i <= 3; i++ {
		packet := transportPacket(t, sessionB, routeKey, uint64(i))
		forward, _ := state.handleClientPacket(packet)
		clientAction, _ := state.decorateClientPacket(packet, forward)
		serverAction, _ := state.decorateServerPacket(packet, true)
		wantDuplicates := 0
		if i <= 2 {
			wantDuplicates = 1
		}
		if clientAction.duplicates != wantDuplicates {
			t.Fatalf("client packet %d duplicates=%d, want %d", i, clientAction.duplicates, wantDuplicates)
		}
		if serverAction.duplicates != wantDuplicates {
			t.Fatalf("server packet %d duplicates=%d, want %d", i, serverAction.duplicates, wantDuplicates)
		}
	}
	if state.sessionByResponse[2] != sessionB {
		t.Fatalf("response 2 session=%#x, want %#x", state.sessionByResponse[2], sessionB)
	}
}

func TestChaosWindowIsFiniteAndMutatesTransport(t *testing.T) {
	var routeKey [32]byte
	routeKey[0] = 0x55
	state, err := newFaultState(modeChaos, 2, routeKey)
	if err != nil {
		t.Fatal(err)
	}
	state.chaosBudget = 80
	bootstrapSession(t, state, routeKey, 0x1111)
	state.handleServerPacket(establishmentPacket(t, routeKey, 2))
	if !state.chaosActive {
		t.Fatal("chaos window was not armed")
	}

	var drops, duplicates, delays int
	for i := 1; i <= 80; i++ {
		packet := transportPacket(t, 0x2222, routeKey, uint64(i))
		forward, _ := state.handleClientPacket(packet)
		action, _ := state.decorateClientPacket(packet, forward)
		if !action.forward {
			drops++
		}
		if action.duplicates > 0 {
			duplicates++
		}
		if action.delay > 0 {
			delays++
		}
	}
	if state.chaosActive || state.chaosRemaining != 0 {
		t.Fatalf("chaos window remained active: active=%v remaining=%d", state.chaosActive, state.chaosRemaining)
	}
	if drops == 0 || duplicates == 0 || delays == 0 {
		t.Fatalf("chaos mutations drops=%d duplicates=%d delays=%d", drops, duplicates, delays)
	}

	packet := transportPacket(t, 0x2222, routeKey, 100)
	forward, _ := state.handleClientPacket(packet)
	action, _ := state.decorateClientPacket(packet, forward)
	if !action.forward || action.duplicates != 0 || action.delay != 0 {
		t.Fatalf("post-chaos action=%+v, want plain forwarding", action)
	}
}

func TestForwardPacketActionDefaults(t *testing.T) {
	action := packetAction{forward: true}
	if !action.forward || action.duplicates != 0 || action.delay != 0*time.Second {
		t.Fatalf("unexpected default action: %+v", action)
	}
}
