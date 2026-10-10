package peerstore

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
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

// WriteAtomic replaces path with a canonical snapshot of records. The file is
// written in the same directory and renamed into place so readers never observe
// a partially written peer set.
func WriteAtomic(path string, records []Record) error {
	if path == "" {
		return fmt.Errorf("peers file path is empty")
	}

	seenIPs := make(map[netip.Addr]struct{}, len(records))
	seenKeys := make(map[noisehandshake.PublicKey]struct{}, len(records))
	for i := range records {
		addr := records[i].TunnelIPv4.Unmap()
		if err := server.ValidateTunnelIPv4(addr); err != nil {
			return fmt.Errorf("peer %d: %w", i, err)
		}
		if _, exists := seenIPs[addr]; exists {
			return fmt.Errorf("peer %d: duplicate tunnel IPv4 %s", i, addr)
		}
		if _, exists := seenKeys[records[i].PublicKey]; exists {
			return fmt.Errorf("peer %d: duplicate client public key", i)
		}
		if records[i].Name != "" && (len(strings.Fields(records[i].Name)) != 1 || strings.Contains(records[i].Name, "#")) {
			return fmt.Errorf("peer %d: name must not contain whitespace or #", i)
		}
		seenIPs[addr] = struct{}{}
		seenKeys[records[i].PublicKey] = struct{}{}
	}

	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary peers file: %w", err)
	}
	temporaryPath := file.Name()
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod temporary peers file: %w", err)
	}
	writer := bufio.NewWriter(file)
	for _, record := range records {
		publicKey := base64.StdEncoding.EncodeToString(record.PublicKey[:])
		addr := record.TunnelIPv4.Unmap()
		if record.Name == "" {
			if _, err := fmt.Fprintf(writer, "%s %s\n", addr, publicKey); err != nil {
				return fmt.Errorf("write temporary peers file: %w", err)
			}
			continue
		}
		if _, err := fmt.Fprintf(writer, "%s %s %s\n", addr, publicKey, record.Name); err != nil {
			return fmt.Errorf("write temporary peers file: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush temporary peers file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary peers file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary peers file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace peers file: %w", err)
	}
	committed = true
	return nil
}
