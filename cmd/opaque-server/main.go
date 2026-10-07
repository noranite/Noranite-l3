package main

import (
	"errors"
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/keyfile"
	"github.com/noranite/Noranite-l3/internal/noisehandshake"
	"github.com/noranite/Noranite-l3/internal/outerudp"
	"github.com/noranite/Noranite-l3/internal/prototype"
	"github.com/noranite/Noranite-l3/internal/server"
	"github.com/noranite/Noranite-l3/internal/tun"
)

func main() {
	tunName := flag.String(
		"tun",
		"ol3s0",
		"TUN interface name",
	)

	mtu := flag.Int(
		"mtu",
		dataplane.ReferenceTunnelMTU,
		"TUN MTU",
	)

	bindText := flag.String(
		"bind",
		"192.0.2.1:51820",
		"outer server UDP bind address",
	)

	routeKeyFile := flag.String(
		"route-key-file",
		"",
		"file containing standard-Base64 encoded 32-byte route key",
	)

	privateKeyFile := flag.String(
		"private-key-file",
		"",
		"file containing standard-Base64 encoded 32-byte server X25519 private key",
	)

	peersFile := flag.String(
		"peers-file",
		"",
		"peer configuration file: one '<tunnel-ipv4> <client-public-key>' per line",
	)

	flag.Parse()

	bind := mustAddrPort(*bindText)

	routeKey, err := keyfile.ReadBase64Key32(*routeKeyFile)
	if err != nil {
		log.Fatalf("load route key: %v", err)
	}
	peerSpecs, err := loadPeerSpecs(*peersFile)
	if err != nil {
		log.Fatalf("load peers: %v", err)
	}

	corePeers := make([]server.PeerConfig, 0, len(peerSpecs))
	authorizedPeers := make([]noisehandshake.AuthorizedPeer, 0, len(peerSpecs))
	for _, peer := range peerSpecs {
		corePeers = append(corePeers, server.PeerConfig{
			TunnelIPv4:     peer.tunnelIPv4,
			InitialSession: nil,
		})
		authorizedPeers = append(authorizedPeers, noisehandshake.AuthorizedPeer{
			TunnelIPv4: peer.tunnelIPv4,
			PublicKey:  peer.publicKey,
		})
	}

	core, err := server.New(server.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: *mtu,
		Lifecycle: server.LifecycleConfig{
			// Lifetime and grace values are operational policy, not wire constants.
			GenerationLifetime: 24 * time.Hour,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: corePeers,
	})
	if err != nil {
		log.Fatalf("create server core: %v", err)
	}

	privateRaw, err := keyfile.ReadBase64Key32(*privateKeyFile)
	if err != nil {
		log.Fatalf("load server private key: %v", err)
	}
	establishmentIngress, err := noisehandshake.NewServer(noisehandshake.ServerConfig{
		Core:             core,
		StaticPrivateKey: noisehandshake.PrivateKey(privateRaw),
		Peers:            authorizedPeers,
	})
	if err != nil {
		log.Fatalf("create Noise establishment provider: %v", err)
	}

	dev, err := tun.Open(*tunName, *mtu)
	if err != nil {
		log.Fatalf("open TUN: %v", err)
	}

	conn, err := outerudp.ListenIPv4(bind)
	if err != nil {
		_ = dev.Close()
		log.Fatalf("listen UDP: %v", err)
	}

	actualName, _ := dev.Name()
	log.Printf(
		"server started: tun=%s udp=%s peers=%d establishment=noise-ik session=none",
		actualName,
		conn.LocalAddr(),
		len(peerSpecs),
	)

	err = prototype.RunServerTunnel(
		dev,
		conn,
		core,
		establishmentIngress,
		*mtu,
	)

	if errors.Is(err, os.ErrClosed) ||
		errors.Is(err, net.ErrClosed) {
		return
	}

	log.Fatalf("server tunnel stopped: %v", err)
}

func mustAddrPort(value string) netip.AddrPort {
	addr, err := netip.ParseAddrPort(value)
	if err != nil {
		log.Fatalf(
			"parse UDP endpoint %q: %v",
			value,
			err,
		)
	}

	if !addr.Addr().Is4() {
		log.Fatalf(
			"UDP endpoint is not IPv4: %s",
			value,
		)
	}

	return addr
}
