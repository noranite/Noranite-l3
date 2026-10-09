package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/keyfile"
	"github.com/noranite/Noranite-l3/internal/noisehandshake"
	"github.com/noranite/Noranite-l3/internal/outerudp"
	"github.com/noranite/Noranite-l3/internal/prototype"
	"github.com/noranite/Noranite-l3/internal/server"
	"github.com/noranite/Noranite-l3/internal/servercontrol"
	"github.com/noranite/Noranite-l3/internal/tun"
)

func main() {
	tunName := flag.String(
		"tun",
		"nrnt0",
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
		"optional bootstrap peer configuration: '<tunnel-ipv4> <client-public-key> [name]' per line",
	)

	controlSocket := flag.String(
		"control-socket",
		servercontrol.DefaultSocketPath,
		"local Unix control socket",
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

	// Runtime peers are always installed through servercontrol.Controller. This
	// keeps startup and live administration on the same mutation path.
	core, err := server.New(server.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: *mtu,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: 24 * time.Hour,
			ReceiveGrace:       5 * time.Second,
		},
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

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	runtimeDone := make(chan struct{})
	go func() {
		select {
		case <-signalCtx.Done():
			_ = dev.Close()
			_ = conn.Close()
		case <-runtimeDone:
		}
	}()

	actualName, _ := dev.Name()
	var controller *servercontrol.Controller
	var controlServer *servercontrol.UnixServer
	shutdownControl := func() {
		if controlServer != nil {
			controlServer.Close()
		}
		if controller != nil {
			controller.Close()
		}
	}

	err = prototype.RunServerTunnelWithHook(
		dev, conn, core, establishmentIngress, *mtu,
		func(rx *server.RXEngine, tx *server.TXEngine) error {
			var controllerErr error
			controller, controllerErr = servercontrol.NewController(core, establishmentIngress, rx, tx)
			if controllerErr != nil {
				return controllerErr
			}
			for i, spec := range peerSpecs {
				if err := controller.SetPeer(servercontrol.Peer{
					TunnelIPv4: spec.TunnelIPv4,
					PublicKey:  spec.PublicKey,
				}); err != nil {
					return fmt.Errorf("install bootstrap peer %d: %w", i, err)
				}
			}
			var controlErr error
			controlServer, controlErr = servercontrol.ListenUnix(*controlSocket, controller)
			if controlErr != nil {
				return controlErr
			}
			log.Printf(
				"server started: tun=%s udp=%s peers=%d control=%s establishment=noise-ik session=none",
				actualName,
				conn.LocalAddr(),
				len(peerSpecs),
				*controlSocket,
			)
			return nil
		},
		shutdownControl,
	)

	close(runtimeDone)
	interrupted := signalCtx.Err() != nil
	stopSignals()
	shutdownControl()
	if interrupted {
		return
	}
	if errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
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
