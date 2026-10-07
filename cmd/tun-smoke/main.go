package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/tun"
)

func main() {
	name := flag.String(
		"name",
		"ol3test0",
		"TUN interface name",
	)
	mtu := flag.Int(
		"mtu",
		dataplane.ReferenceTunnelMTU,
		"TUN MTU",
	)

	flag.Parse()

	dev, err := tun.Open(*name, *mtu)
	if err != nil {
		log.Fatalf("open TUN: %v", err)
	}
	defer dev.Close()

	actualName, err := dev.Name()
	if err != nil {
		log.Fatalf("get TUN name: %v", err)
	}

	actualMTU, err := dev.MTU()
	if err != nil {
		log.Fatalf("get TUN MTU: %v", err)
	}

	log.Printf(
		"TUN created: name=%s mtu=%d batch=%d",
		actualName,
		actualMTU,
		dev.BatchSize(),
	)

	go logEvents(dev)

	if err := readLoop(dev, actualMTU); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return
		}
		log.Fatalf("TUN read: %v", err)
	}
}

func readLoop(dev tun.Device, mtu int) error {
	batchSize := dev.BatchSize()
	if batchSize < 1 {
		return fmt.Errorf("invalid TUN batch size %d", batchSize)
	}

	// Match the TX buffer layout so SealDataTo can reuse the allocation:
	//
	//	[ RouteSize headroom ][ IPv4 packet ][ DATA padding ][ AEAD tag ]
	//
	bufferSize :=
		dataplane.RouteSize +
			mtu +
			dataplane.MaxDataPadding +
			dataplane.TagSize

	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)

	for i := range bufs {
		bufs[i] = make([]byte, bufferSize)
	}

	for {
		n, err := dev.Read(
			bufs,
			sizes,
			dataplane.RouteSize,
		)
		if err != nil {
			return err
		}

		for i := 0; i < n; i++ {
			size := sizes[i]

			if size <= 0 || size > mtu {
				log.Printf(
					"drop unexpected TUN packet size=%d",
					size,
				)
				continue
			}

			packet := bufs[i][dataplane.RouteSize : dataplane.RouteSize+size]

			version := packet[0] >> 4

			log.Printf(
				"TUN RX: len=%d ip-version=%d",
				len(packet),
				version,
			)
		}
	}
}

func logEvents(dev tun.Device) {
	for event := range dev.Events() {
		switch {
		case event&tun.EventMTUUpdate != 0:
			mtu, err := dev.MTU()
			if err != nil {
				log.Printf("TUN MTU update: %v", err)
			} else {
				log.Printf("TUN MTU updated: %d", mtu)
			}

		case event&tun.EventUp != 0:
			log.Printf("TUN is up")

		case event&tun.EventDown != 0:
			log.Printf("TUN is down")
		}
	}
}
