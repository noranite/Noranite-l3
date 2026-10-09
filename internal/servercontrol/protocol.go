package servercontrol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/noranite/Noranite-l3/internal/noisehandshake"
)

const (
	DefaultSocketPath       = "/run/noranite/control.sock"
	maxRequestBytes         = 64 << 10
	maxResponseBytes        = 4 << 20
	requestTimeout          = 5 * time.Second
	staleSocketProbeTimeout = 250 * time.Millisecond
)

const (
	OperationPeerList   = "peer.list"
	OperationPeerSet    = "peer.set"
	OperationPeerRemove = "peer.remove"
)

const ErrorCodePeerConflict = "peer_conflict"

type WirePeer struct {
	IP        string `json:"ip"`
	PublicKey string `json:"public_key"`
}

type Request struct {
	Operation string    `json:"op"`
	Peer      *WirePeer `json:"peer,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
}

type Response struct {
	OK        bool       `json:"ok"`
	Error     string     `json:"error,omitempty"`
	ErrorCode string     `json:"error_code,omitempty"`
	Peers     []WirePeer `json:"peers,omitempty"`
}

type UnixServer struct {
	controller *Controller
	listener   *net.UnixListener

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

func ListenUnix(path string, controller *Controller) (*UnixServer, error) {
	if path == "" {
		return nil, fmt.Errorf("control socket path is empty")
	}
	if controller == nil {
		return nil, fmt.Errorf("peer controller is nil")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create control socket directory: %w", err)
	}
	listener, err := listenUnixReplacingStale(path)
	if err != nil {
		return nil, fmt.Errorf("listen control socket %q: %w", path, err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("chmod control socket %q: %w", path, err)
	}

	s := &UnixServer{
		controller: controller,
		listener:   listener,
		conns:      make(map[net.Conn]struct{}),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

func listenUnixReplacingStale(path string) (*net.UnixListener, error) {
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err == nil || !errors.Is(err, syscall.EADDRINUSE) {
		return listener, err
	}

	info, statErr := os.Lstat(path)
	if statErr != nil || info.Mode()&os.ModeSocket == 0 {
		return nil, err
	}

	probe, probeErr := net.DialTimeout("unix", path, staleSocketProbeTimeout)
	if probeErr == nil {
		_ = probe.Close()
		return nil, err
	}
	if !errors.Is(probeErr, syscall.ECONNREFUSED) {
		return nil, err
	}

	if removeErr := os.Remove(path); removeErr != nil {
		return nil, fmt.Errorf("remove stale control socket: %w", removeErr)
	}
	return net.ListenUnix("unix", addr)
}

func (s *UnixServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handleConn(conn)
	}
}

func (s *UnixServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))

	reader := bufio.NewReaderSize(conn, maxRequestBytes+1)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		message := "request must be one newline-terminated JSON value"
		if errors.Is(err, bufio.ErrBufferFull) {
			message = "request is too large"
		}
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: message})
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var req Request
	if err := decoder.Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: "invalid request: " + err.Error()})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: "request must contain one JSON value"})
		return
	}
	response := s.execute(req)
	_ = json.NewEncoder(conn).Encode(response)
}

func (s *UnixServer) execute(req Request) Response {
	switch req.Operation {
	case OperationPeerList:
		peers, err := s.controller.ListPeers()
		if err != nil {
			return responseError(err)
		}
		rows := make([]WirePeer, 0, len(peers))
		for _, peer := range peers {
			rows = append(rows, wirePeer(peer))
		}
		return Response{OK: true, Peers: rows}

	case OperationPeerSet:
		if req.Peer == nil {
			return responseError(fmt.Errorf("peer.set requires peer"))
		}
		peer, err := parseWirePeer(*req.Peer)
		if err != nil {
			return responseError(err)
		}
		if err := s.controller.SetPeer(peer); err != nil {
			return responseError(err)
		}
		return Response{OK: true}

	case OperationPeerRemove:
		key, err := noisehandshake.ParsePublicKey(req.PublicKey)
		if err != nil {
			return responseError(fmt.Errorf("parse public key: %w", err))
		}
		if err := s.controller.RemovePeer(key); err != nil {
			return responseError(err)
		}
		return Response{OK: true}

	default:
		return responseError(fmt.Errorf("unknown operation %q", req.Operation))
	}
}

func (s *UnixServer) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return
	}
	s.closed = true
	listener := s.listener
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	_ = listener.Close()
	for _, conn := range conns {
		_ = conn.Close()
	}
	s.wg.Wait()
}

func Do(path string, request Request) (Response, error) {
	conn, err := net.DialTimeout("unix", path, requestTimeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return Response{}, err
	}
	var response Response
	if err := json.NewDecoder(io.LimitReader(conn, maxResponseBytes)).Decode(&response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func wirePeer(peer Peer) WirePeer {
	return WirePeer{
		IP:        peer.TunnelIPv4.String(),
		PublicKey: EncodePublicKey(peer.PublicKey),
	}
}

func parseWirePeer(peer WirePeer) (Peer, error) {
	ip, err := netip.ParseAddr(peer.IP)
	if err != nil {
		return Peer{}, fmt.Errorf("parse tunnel IPv4: %w", err)
	}
	key, err := noisehandshake.ParsePublicKey(peer.PublicKey)
	if err != nil {
		return Peer{}, fmt.Errorf("parse public key: %w", err)
	}
	return Peer{TunnelIPv4: ip.Unmap(), PublicKey: key}, nil
}

func responseError(err error) Response {
	response := Response{OK: false, Error: err.Error()}
	if errors.Is(err, ErrPeerConflict) {
		response.ErrorCode = ErrorCodePeerConflict
	}
	return response
}
