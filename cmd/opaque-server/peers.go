package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/noranite/Noranite-l3/internal/noisehandshake"
)

type peerSpec struct {
	tunnelIPv4 netip.Addr
	publicKey  noisehandshake.PublicKey
}

func loadPeerSpecs(path string) ([]peerSpec, error) {
	if path == "" {
		return nil, fmt.Errorf("peers file path is empty")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open peers file %q: %w", path, err)
	}
	defer file.Close()

	var specs []peerSpec
	seenIPs := make(map[netip.Addr]struct{})
	seenKeys := make(map[noisehandshake.PublicKey]struct{})
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf(
				"peers file %q line %d: want '<tunnel-ipv4> <client-public-key>'",
				path,
				lineNumber,
			)
		}

		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			return nil, fmt.Errorf("peers file %q line %d: parse tunnel IPv4: %w", path, lineNumber, err)
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			return nil, fmt.Errorf("peers file %q line %d: tunnel address is not IPv4: %s", path, lineNumber, fields[0])
		}
		if _, exists := seenIPs[addr]; exists {
			return nil, fmt.Errorf("peers file %q line %d: duplicate tunnel IPv4 %s", path, lineNumber, addr)
		}

		publicKey, err := noisehandshake.ParsePublicKey(fields[1])
		if err != nil {
			return nil, fmt.Errorf("peers file %q line %d: parse client public key: %w", path, lineNumber, err)
		}
		if _, exists := seenKeys[publicKey]; exists {
			return nil, fmt.Errorf("peers file %q line %d: duplicate client public key", path, lineNumber)
		}

		seenIPs[addr] = struct{}{}
		seenKeys[publicKey] = struct{}{}
		specs = append(specs, peerSpec{tunnelIPv4: addr, publicKey: publicKey})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read peers file %q: %w", path, err)
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("peers file %q contains no peers", path)
	}
	return specs, nil
}
