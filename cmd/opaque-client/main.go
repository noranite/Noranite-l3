package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/keyfile"
	"github.com/noranite/Noranite-l3/internal/noisehandshake"
	"github.com/noranite/Noranite-l3/internal/outerudp"
	"github.com/noranite/Noranite-l3/internal/prototype"
	"github.com/noranite/Noranite-l3/internal/tun"
)

func main() {
	tunName := flag.String(
		"tun",
		"ol3c0",
		"TUN interface name",
	)

	mtu := flag.Int(
		"mtu",
		dataplane.ReferenceTunnelMTU,
		"TUN MTU",
	)

	tunnelIPv4Text := flag.String(
		"tunnel-ip",
		"10.66.0.2",
		"client tunnel IPv4",
	)

	bindText := flag.String(
		"bind",
		"192.0.2.2:0",
		"outer client UDP bind address",
	)

	serverText := flag.String(
		"server",
		"192.0.2.1:51820",
		"outer server UDP endpoint",
	)

	routeKeyFile := flag.String(
		"route-key-file",
		"",
		"file containing standard-Base64 encoded 32-byte route key",
	)

	privateKeyFile := flag.String(
		"private-key-file",
		"",
		"file containing standard-Base64 encoded 32-byte client X25519 private key",
	)

	serverPublicKeyText := flag.String(
		"server-public-key",
		"",
		"standard-Base64 encoded server X25519 public key",
	)

	softRekeyAfter := flag.Duration(
		"soft-rekey-after",
		12*time.Hour,
		"traffic Session soft-rekey interval",
	)

	establishmentRetryMin := flag.Duration(
		"establishment-retry-min",
		2500*time.Millisecond,
		"minimum Session establishment retry delay",
	)

	establishmentRetryMax := flag.Duration(
		"establishment-retry-max",
		3500*time.Millisecond,
		"maximum Session establishment retry delay",
	)

	keepaliveIntervalMin := flag.Duration(
		"keepalive-interval-min",
		25*time.Second,
		"minimum authenticated Session KEEPALIVE interval (all keepalive values 0 disables)",
	)

	keepaliveIntervalMax := flag.Duration(
		"keepalive-interval-max",
		35*time.Second,
		"maximum authenticated Session KEEPALIVE interval (all keepalive values 0 disables)",
	)

	keepaliveTimeout := flag.Duration(
		"keepalive-timeout",
		2*time.Second,
		"authenticated Session KEEPALIVE ACK timeout (all keepalive values 0 disables)",
	)

	flag.Parse()

	tunnelIPv4 := mustIPv4(*tunnelIPv4Text)
	bind := mustAddrPort(*bindText)
	serverEndpoint := mustAddrPort(*serverText)

	routeKey, err := keyfile.ReadBase64Key32(*routeKeyFile)
	if err != nil {
		log.Fatalf("load route key: %v", err)
	}

	privateRaw, err := keyfile.ReadBase64Key32(*privateKeyFile)
	if err != nil {
		log.Fatalf("load client private key: %v", err)
	}
	serverPublicKey, err := noisehandshake.ParsePublicKey(*serverPublicKeyText)
	if err != nil {
		log.Fatalf("parse server public key: %v", err)
	}
	factory, err := noisehandshake.NewClient(noisehandshake.ClientConfig{
		ServerEndpoint:   serverEndpoint,
		RouteKey:         routeKey,
		StaticPrivateKey: noisehandshake.PrivateKey(privateRaw),
		ServerPublicKey:  serverPublicKey,
	})
	if err != nil {
		log.Fatalf("create Noise establishment factory: %v", err)
	}

	conn, err := outerudp.ListenIPv4(bind)
	if err != nil {
		log.Fatalf("listen UDP: %v", err)
	}

	const generationLifetime = 24 * time.Hour

	core, err := client.New(client.Config{
		RouteKey:           routeKey,
		TunnelIPv4:         tunnelIPv4,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: *mtu,
		Lifecycle: client.LifecycleConfig{
			GenerationLifetime: generationLifetime,
			ReceiveGrace:       5 * time.Second,
		},
		Session: nil,
	})
	if err != nil {
		_ = conn.Close()
		log.Fatalf("create client core: %v", err)
	}

	dev, err := tun.Open(*tunName, *mtu)
	if err != nil {
		_ = conn.Close()
		log.Fatalf("open TUN: %v", err)
	}

	runtime, err := prototype.NewClientRuntime(
		dev,
		conn,
		core,
		*mtu,
		prototype.ClientRuntimeConfig{},
	)
	if err != nil {
		_ = dev.Close()
		_ = conn.Close()
		log.Fatalf("create client runtime: %v", err)
	}

	controller, err := client.NewSessionController(
		core,
		runtime,
		factory,
		client.SessionControllerConfig{
			SoftRekeyAfter:        *softRekeyAfter,
			EstablishmentRetryMin: *establishmentRetryMin,
			EstablishmentRetryMax: *establishmentRetryMax,
			KeepaliveIntervalMin:  *keepaliveIntervalMin,
			KeepaliveIntervalMax:  *keepaliveIntervalMax,
			KeepaliveTimeout:      *keepaliveTimeout,
		},
	)
	if err != nil {
		_ = dev.Close()
		_ = conn.Close()
		log.Fatalf("create Session controller: %v", err)
	}
	if err := runtime.SetDatagramDemux(controller); err != nil {
		_ = dev.Close()
		_ = conn.Close()
		log.Fatalf("install Session controller demux: %v", err)
	}

	actualName, _ := dev.Name()
	log.Printf(
		"client started: tun=%s tunnel=%s udp=%s server=%s establishment=noise-ik session=none soft_rekey_after=%s retry=%s..%s keepalive_interval=%s..%s keepalive_timeout=%s",
		actualName,
		tunnelIPv4,
		conn.LocalAddr(),
		serverEndpoint,
		*softRekeyAfter,
		*establishmentRetryMin,
		*establishmentRetryMax,
		*keepaliveIntervalMin,
		*keepaliveIntervalMax,
		*keepaliveTimeout,
	)

	err = runClient(runtime, core, controller)

	if errors.Is(err, os.ErrClosed) ||
		errors.Is(err, net.ErrClosed) {
		return
	}

	log.Fatalf("client tunnel stopped: %v", err)
}

func runClient(
	runtime *prototype.ClientRuntime,
	core *client.Core,
	controller *client.SessionController,
) error {
	if controller == nil {
		return errors.New("session controller is nil")
	}

	controllerDone := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rekeySignal := make(chan os.Signal, 1)
	signal.Notify(rekeySignal, syscall.SIGUSR1)
	defer signal.Stop(rekeySignal)

	go func() {
		var watchCancel context.CancelFunc
		defer func() {
			if watchCancel != nil {
				watchCancel()
			}
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case <-runtime.Done():
				return
			case <-rekeySignal:
				requestedAt := time.Now()
				current := core.Session()
				if current == nil {
					log.Printf("rekey requested by SIGUSR1 with no current Session")
					controller.RequestRekey()
					continue
				}

				previousID := current.ID()
				log.Printf(
					"rekey requested by SIGUSR1: current=%016x",
					previousID,
				)
				controller.RequestRekey()

				if watchCancel != nil {
					watchCancel()
				}
				watchCtx, cancelWatch := context.WithCancel(ctx)
				watchCancel = cancelWatch
				go logRekeyCompletion(
					watchCtx,
					runtime.Done(),
					core,
					previousID,
					requestedAt,
				)
			}
		}
	}()

	go func() {
		err := controller.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			runtime.Close()
		}
		controllerDone <- err
	}()

	runtimeErr := runtime.Run()
	cancel()
	controllerErr := <-controllerDone
	if controllerErr != nil && !errors.Is(controllerErr, context.Canceled) {
		return controllerErr
	}
	return runtimeErr
}

func logRekeyCompletion(
	ctx context.Context,
	runtimeDone <-chan struct{},
	core *client.Core,
	previousID uint64,
	requestedAt time.Time,
) {
	// Keep polling well below the retry interval so latency logs distinguish a
	// normal completion from a retry-sized stall.
	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()

	for {
		current := core.Session()
		if current != nil && current.ID() != previousID {
			latency := time.Since(requestedAt)
			log.Printf(
				"rekey completed: previous=%016x current=%016x latency=%s latency_ns=%d",
				previousID,
				current.ID(),
				latency,
				latency.Nanoseconds(),
			)
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-runtimeDone:
			return
		case <-ticker.C:
		}
	}
}

func mustIPv4(value string) netip.Addr {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		log.Fatalf(
			"parse IPv4 %q: %v",
			value,
			err,
		)
	}

	if !addr.Is4() {
		log.Fatalf(
			"address is not IPv4: %s",
			value,
		)
	}

	return addr
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
