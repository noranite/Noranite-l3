package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/keyfile"
)

const (
	oldGenerationEarlyDelay = 1 * time.Second
	oldGenerationLateDelay  = 7 * time.Second
	rekeyResponseDelay      = 500 * time.Millisecond
	defaultChaosPackets     = 240
)

type proxyMode string

const (
	modePass                            proxyMode = "pass"
	modeDropResponse                    proxyMode = "drop-response"
	modeDropResponsesFromTarget         proxyMode = "drop-responses-from-target"
	modeDropFirstTransportAfterResponse proxyMode = "drop-first-transport-after-response"
	modeBlockTransportUntilNextResponse proxyMode = "block-transport-until-next-response"
	modeDelayOldGeneration              proxyMode = "delay-old-generation"
	modeDuplicateReplay                 proxyMode = "duplicate-replay"
	modeChaos                           proxyMode = "chaos"
)

type packetAction struct {
	forward      bool
	duplicates   int
	delay        time.Duration
	releaseEvent string
}

type faultState struct {
	mode           proxyMode
	targetResponse int
	chaosBudget    int

	serverResponses int
	clientInits     int

	dropNextClientTransport bool
	blockClientTransport    bool
	blockedTransportDrops   int

	routeScratch *dataplane.DataScratch

	// A Noise RESPONSE hides the generated traffic session ID. The proxy learns
	// that ID from the first client transport datagram on a different session
	// after the forwarded RESPONSE. This keeps the fault harness outside Noise
	// payload semantics: it understands only the opaque route namespace.
	pendingSessionResponse int
	currentClientSession   uint64
	sessionByResponse      map[int]uint64

	oldDelayArmed bool
	oldSessionID  uint64
	oldDelayed    int

	clientTransportBySession map[uint64]int
	serverTransportBySession map[uint64]int

	chaosActive    bool
	chaosRemaining int
	chaosSeen      int
}

func newFaultState(mode proxyMode, targetResponse int, routeKey [32]byte) (*faultState, error) {
	switch mode {
	case modePass,
		modeDropResponse,
		modeDropResponsesFromTarget,
		modeDropFirstTransportAfterResponse,
		modeBlockTransportUntilNextResponse,
		modeDelayOldGeneration,
		modeDuplicateReplay,
		modeChaos:
	default:
		return nil, fmt.Errorf("unknown mode %q", mode)
	}
	if targetResponse <= 0 {
		return nil, fmt.Errorf("target response ordinal must be positive")
	}
	scratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		return nil, fmt.Errorf("create route decoder: %w", err)
	}
	return &faultState{
		mode:                     mode,
		targetResponse:           targetResponse,
		chaosBudget:              defaultChaosPackets,
		routeScratch:             scratch,
		sessionByResponse:        make(map[int]uint64),
		clientTransportBySession: make(map[uint64]int),
		serverTransportBySession: make(map[uint64]int),
	}, nil
}

func (s *faultState) decodeRoute(packet []byte) (dataplane.Route, bool) {
	route, err := dataplane.DecodeRoute(s.routeScratch, packet)
	if err != nil {
		return dataplane.Route{}, false
	}
	return route, true
}

func (s *faultState) observeClientTransport(route dataplane.Route) []string {
	if route.SessionID == 0 {
		return nil
	}
	if s.currentClientSession == 0 {
		s.currentClientSession = route.SessionID
		if s.pendingSessionResponse != 0 {
			ordinal := s.pendingSessionResponse
			s.pendingSessionResponse = 0
			s.sessionByResponse[ordinal] = route.SessionID
			return []string{fmt.Sprintf(
				"transport session learned response_ordinal=%d session=%016x",
				ordinal,
				route.SessionID,
			)}
		}
		return []string{fmt.Sprintf("transport session learned session=%016x", route.SessionID)}
	}

	if s.pendingSessionResponse != 0 && route.SessionID != s.currentClientSession {
		ordinal := s.pendingSessionResponse
		s.pendingSessionResponse = 0
		s.currentClientSession = route.SessionID
		s.sessionByResponse[ordinal] = route.SessionID
		return []string{fmt.Sprintf(
			"transport session learned response_ordinal=%d session=%016x",
			ordinal,
			route.SessionID,
		)}
	}
	return nil
}

func (s *faultState) handleServerPacket(packet []byte) (forward bool, events []string) {
	route, ok := s.decodeRoute(packet)
	if !ok || route.SessionID != 0 {
		return true, nil
	}

	s.serverResponses++
	ordinal := s.serverResponses
	events = append(events, fmt.Sprintf(
		"Noise RESPONSE ordinal=%d exchange=%016x observed",
		ordinal,
		route.Sequence,
	))

	if s.mode == modeDropResponse && ordinal == s.targetResponse {
		return false, append(events, fmt.Sprintf("Noise RESPONSE ordinal=%d dropped", ordinal))
	}
	if s.mode == modeDropResponsesFromTarget && ordinal >= s.targetResponse {
		return false, append(events, fmt.Sprintf("Noise RESPONSE ordinal=%d dropped", ordinal))
	}

	// Only a RESPONSE actually forwarded to the client can create a client-side
	// traffic generation. The session ID is learned later from route metadata.
	s.pendingSessionResponse = ordinal

	switch s.mode {
	case modeDropFirstTransportAfterResponse:
		if ordinal == s.targetResponse {
			s.dropNextClientTransport = true
			events = append(events, fmt.Sprintf(
				"armed one client transport drop after Noise RESPONSE ordinal=%d",
				ordinal,
			))
		}
	case modeBlockTransportUntilNextResponse:
		if ordinal == s.targetResponse {
			s.blockClientTransport = true
			s.blockedTransportDrops = 0
			events = append(events, fmt.Sprintf(
				"client transport blocking enabled after Noise RESPONSE ordinal=%d",
				ordinal,
			))
		} else if ordinal == s.targetResponse+1 && s.blockClientTransport {
			s.blockClientTransport = false
			events = append(events, fmt.Sprintf(
				"client transport blocking disabled by Noise RESPONSE ordinal=%d dropped=%d",
				ordinal,
				s.blockedTransportDrops,
			))
		}
	case modeChaos:
		if ordinal == s.targetResponse && !s.chaosActive {
			s.chaosActive = true
			s.chaosRemaining = s.chaosBudget
			s.chaosSeen = 0
			events = append(events, fmt.Sprintf(
				"chaos window armed after Noise RESPONSE ordinal=%d packets=%d",
				ordinal,
				s.chaosBudget,
			))
		}
	}

	events = append(events, fmt.Sprintf("Noise RESPONSE ordinal=%d forwarded", ordinal))
	return true, events
}

func (s *faultState) handleClientPacket(packet []byte) (forward bool, events []string) {
	route, ok := s.decodeRoute(packet)
	if !ok {
		return true, nil
	}
	if route.SessionID == 0 {
		s.clientInits++
		events = append(events, fmt.Sprintf(
			"Noise INIT ordinal=%d exchange=%016x forwarded",
			s.clientInits,
			route.Sequence,
		))
		if s.mode == modeDelayOldGeneration &&
			s.clientInits == s.targetResponse &&
			s.currentClientSession != 0 {
			s.oldDelayArmed = true
			s.oldSessionID = s.currentClientSession
			s.oldDelayed = 0
			events = append(events, fmt.Sprintf(
				"old-generation delay armed after Noise INIT ordinal=%d old_session=%016x",
				s.clientInits,
				s.oldSessionID,
			))
		}
		return true, events
	}

	events = append(events, s.observeClientTransport(route)...)

	if s.dropNextClientTransport {
		s.dropNextClientTransport = false
		return false, append(events, fmt.Sprintf(
			"client transport dropped after Noise RESPONSE ordinal=%d",
			s.targetResponse,
		))
	}

	if s.blockClientTransport {
		s.blockedTransportDrops++
		if s.blockedTransportDrops == 1 {
			return false, append(events, fmt.Sprintf(
				"client transport dropped while blocked after Noise RESPONSE ordinal=%d",
				s.targetResponse,
			))
		}
		return false, events
	}

	return true, events
}

func (s *faultState) decorateServerPacket(packet []byte, forward bool) (packetAction, []string) {
	action := packetAction{forward: forward}
	if !forward {
		return action, nil
	}

	route, ok := s.decodeRoute(packet)
	if !ok {
		return action, nil
	}
	if route.SessionID == 0 {
		if s.mode == modeDelayOldGeneration && s.serverResponses == s.targetResponse {
			action.delay = rekeyResponseDelay
			action.releaseEvent = fmt.Sprintf(
				"delayed Noise RESPONSE ordinal=%d released",
				s.targetResponse,
			)
			return action, []string{fmt.Sprintf(
				"Noise RESPONSE ordinal=%d delayed by %s",
				s.targetResponse,
				rekeyResponseDelay,
			)}
		}
		return action, nil
	}

	switch s.mode {
	case modeDuplicateReplay:
		targetID := s.sessionByResponse[s.targetResponse]
		if targetID != 0 && route.SessionID == targetID {
			s.serverTransportBySession[route.SessionID]++
			ordinal := s.serverTransportBySession[route.SessionID]
			if ordinal <= 2 {
				action.duplicates = 1
				return action, []string{fmt.Sprintf(
					"server transport duplicated response_ordinal=%d transport_ordinal=%d sequence=%d",
					s.targetResponse,
					ordinal,
					route.Sequence,
				)}
			}
		}
	case modeChaos:
		return s.decorateChaos(action, "server", route)
	}

	return action, nil
}

func (s *faultState) decorateClientPacket(packet []byte, forward bool) (packetAction, []string) {
	action := packetAction{forward: forward}
	if !forward {
		return action, nil
	}

	route, ok := s.decodeRoute(packet)
	if !ok || route.SessionID == 0 {
		return action, nil
	}

	switch s.mode {
	case modeDelayOldGeneration:
		if s.oldDelayArmed && s.oldSessionID != 0 && route.SessionID == s.oldSessionID && s.oldDelayed < 4 {
			s.oldDelayed++
			index := s.oldDelayed
			class := "early"
			delay := oldGenerationEarlyDelay
			if index > 2 {
				class = "late"
				delay = oldGenerationLateDelay
			}
			action.delay = delay
			action.releaseEvent = fmt.Sprintf(
				"old-generation delayed packet released class=%s index=%d session=%016x sequence=%d",
				class,
				index,
				route.SessionID,
				route.Sequence,
			)
			return action, []string{fmt.Sprintf(
				"old-generation client transport delayed class=%s index=%d session=%016x sequence=%d delay=%s",
				class,
				index,
				route.SessionID,
				route.Sequence,
				delay,
			)}
		}
	case modeDuplicateReplay:
		targetID := s.sessionByResponse[s.targetResponse]
		if targetID != 0 && route.SessionID == targetID {
			s.clientTransportBySession[route.SessionID]++
			ordinal := s.clientTransportBySession[route.SessionID]
			if ordinal <= 2 {
				action.duplicates = 1
				return action, []string{fmt.Sprintf(
					"client transport duplicated response_ordinal=%d transport_ordinal=%d sequence=%d",
					s.targetResponse,
					ordinal,
					route.Sequence,
				)}
			}
		}
	case modeChaos:
		return s.decorateChaos(action, "client", route)
	}

	return action, nil
}

func (s *faultState) decorateChaos(
	action packetAction,
	direction string,
	route dataplane.Route,
) (packetAction, []string) {
	if !s.chaosActive || s.chaosRemaining <= 0 {
		return action, nil
	}

	s.chaosSeen++
	ordinal := s.chaosSeen
	s.chaosRemaining--

	var events []string
	phase := ordinal % 31
	if phase == 15 || phase == 16 {
		action.forward = false
		events = append(events, fmt.Sprintf(
			"chaos transport dropped ordinal=%d direction=%s session=%016x sequence=%d",
			ordinal,
			direction,
			route.SessionID,
			route.Sequence,
		))
	} else {
		if ordinal%11 == 0 {
			action.duplicates = 1
			events = append(events, fmt.Sprintf(
				"chaos transport duplicated ordinal=%d direction=%s",
				ordinal,
				direction,
			))
		}
		if ordinal%29 == 0 {
			action.delay = 120 * time.Millisecond
		} else if ordinal%7 == 0 {
			action.delay = 35 * time.Millisecond
		}
		if action.delay > 0 {
			events = append(events, fmt.Sprintf(
				"chaos transport delayed ordinal=%d direction=%s delay=%s",
				ordinal,
				direction,
				action.delay,
			))
		}
	}

	if s.chaosRemaining == 0 {
		s.chaosActive = false
		events = append(events, fmt.Sprintf(
			"chaos window complete packets=%d",
			s.chaosSeen,
		))
	}
	return action, events
}

func forwardPacket(
	conn *net.UDPConn,
	packet []byte,
	destination netip.AddrPort,
	action packetAction,
) error {
	if !action.forward {
		return nil
	}

	copies := 1 + action.duplicates
	if action.delay <= 0 {
		for i := 0; i < copies; i++ {
			if _, err := conn.WriteToUDPAddrPort(packet, destination); err != nil {
				return err
			}
		}
		return nil
	}

	payload := bytes.Clone(packet)
	go func() {
		time.Sleep(action.delay)
		for i := 0; i < copies; i++ {
			if _, err := conn.WriteToUDPAddrPort(payload, destination); err != nil {
				log.Printf("delayed UDP forward failed: %v", err)
				return
			}
		}
		if action.releaseEvent != "" {
			log.Print(action.releaseEvent)
		}
	}()
	return nil
}

func main() {
	listenText := flag.String("listen", "192.0.2.2:51821", "proxy UDP listen endpoint")
	serverText := flag.String("server", "192.0.2.1:51820", "real server UDP endpoint")
	routeKeyFile := flag.String("route-key-file", "", "standard-Base64 encoded 32-byte route key file")
	modeText := flag.String("mode", string(modePass), "fault mode")
	targetResponse := flag.Int(
		"target-response",
		2,
		"Noise RESPONSE ordinal targeted by the selected fault (bootstrap is ordinal 1)",
	)
	chaosPackets := flag.Int(
		"chaos-packets",
		defaultChaosPackets,
		"number of encrypted transport datagrams in the deterministic chaos window",
	)
	flag.Parse()

	listen, err := netip.ParseAddrPort(*listenText)
	if err != nil || !listen.Addr().Unmap().Is4() || listen.Port() == 0 {
		log.Fatalf("invalid -listen %q", *listenText)
	}
	listen = netip.AddrPortFrom(listen.Addr().Unmap(), listen.Port())

	server, err := netip.ParseAddrPort(*serverText)
	if err != nil || !server.Addr().Unmap().Is4() || server.Port() == 0 {
		log.Fatalf("invalid -server %q", *serverText)
	}
	server = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())

	routeKey, err := keyfile.ReadBase64Key32(*routeKeyFile)
	if err != nil {
		log.Fatalf("load route key: %v", err)
	}

	state, err := newFaultState(proxyMode(*modeText), *targetResponse, routeKey)
	if err != nil {
		log.Fatal(err)
	}
	if *chaosPackets <= 0 {
		log.Fatalf("-chaos-packets must be positive")
	}
	state.chaosBudget = *chaosPackets

	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(listen))
	if err != nil {
		log.Fatalf("listen UDP: %v", err)
	}
	defer conn.Close()

	log.Printf(
		"proxy started: listen=%s server=%s mode=%s target_response=%d",
		listen,
		server,
		state.mode,
		state.targetResponse,
	)

	buffer := make([]byte, 65535)
	var client netip.AddrPort

	for {
		n, source, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			log.Fatalf("read UDP: %v", err)
		}
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		packet := buffer[:n]

		if source == server {
			if !client.IsValid() {
				log.Printf("dropping server packet before client endpoint is known")
				continue
			}

			forward, events := state.handleServerPacket(packet)
			for _, event := range events {
				log.Print(event)
			}
			action, events := state.decorateServerPacket(packet, forward)
			for _, event := range events {
				log.Print(event)
			}
			if err := forwardPacket(conn, packet, client, action); err != nil {
				log.Fatalf("forward server -> client: %v", err)
			}
			continue
		}

		if !client.IsValid() {
			client = source
			log.Printf("client endpoint learned: %s", client)
		} else if source != client {
			log.Printf("dropping packet from unexpected non-server endpoint: %s", source)
			continue
		}

		forward, events := state.handleClientPacket(packet)
		for _, event := range events {
			log.Print(event)
		}
		action, events := state.decorateClientPacket(packet, forward)
		for _, event := range events {
			log.Print(event)
		}
		if err := forwardPacket(conn, packet, server, action); err != nil {
			log.Fatalf("forward client -> server: %v", err)
		}
	}
}
