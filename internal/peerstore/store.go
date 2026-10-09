package peerstore

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/noranite/Noranite-l3/internal/noisehandshake"
	"github.com/noranite/Noranite-l3/internal/server"
)

// Record is persistent/provisioning metadata. Name is intentionally not part
// of servercontrol.Peer; runtime identity is only PublicKey + TunnelIPv4.
type Record struct {
	Name       string
	TunnelIPv4 netip.Addr
	PublicKey  noisehandshake.PublicKey
}

func Load(path string) ([]Record, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open peers file %q: %w", path, err)
	}
	defer file.Close()
	return Parse(file, path)
}

func Parse(reader io.Reader, source string) ([]Record, error) {
	var records []Record
	seenIPs := make(map[netip.Addr]struct{})
	seenKeys := make(map[noisehandshake.PublicKey]struct{})
	scanner := bufio.NewScanner(reader)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || len(fields) > 3 {
			return nil, fmt.Errorf(
				"peers file %q line %d: want '<tunnel-ipv4> <client-public-key> [name]'",
				source,
				lineNumber,
			)
		}

		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			return nil, fmt.Errorf("peers file %q line %d: parse tunnel IPv4: %w", source, lineNumber, err)
		}
		addr = addr.Unmap()
		if err := server.ValidateTunnelIPv4(addr); err != nil {
			return nil, fmt.Errorf("peers file %q line %d: %w", source, lineNumber, err)
		}
		if _, exists := seenIPs[addr]; exists {
			return nil, fmt.Errorf("peers file %q line %d: duplicate tunnel IPv4 %s", source, lineNumber, addr)
		}

		publicKey, err := noisehandshake.ParsePublicKey(fields[1])
		if err != nil {
			return nil, fmt.Errorf("peers file %q line %d: parse client public key: %w", source, lineNumber, err)
		}
		if _, exists := seenKeys[publicKey]; exists {
			return nil, fmt.Errorf("peers file %q line %d: duplicate client public key", source, lineNumber)
		}

		name := ""
		if len(fields) == 3 {
			name = fields[2]
		}
		seenIPs[addr] = struct{}{}
		seenKeys[publicKey] = struct{}{}
		records = append(records, Record{Name: name, TunnelIPv4: addr, PublicKey: publicKey})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read peers file %q: %w", source, err)
	}
	return records, nil
}
