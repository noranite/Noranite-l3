package keyfile

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const keySize = 32

// ReadBase64Key32 reads one standard-Base64 encoded 32-byte key from path.
// Surrounding ASCII/Unicode whitespace is ignored so a normal trailing newline
// in a secret file is harmless. Embedded whitespace remains invalid Base64.
func ReadBase64Key32(path string) ([keySize]byte, error) {
	var key [keySize]byte
	if path == "" {
		return key, fmt.Errorf("key file path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return key, fmt.Errorf("read key file %q: %w", path, err)
	}
	encoded := strings.TrimSpace(string(data))
	if encoded == "" {
		return key, fmt.Errorf("key file %q is empty", path)
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return key, fmt.Errorf("decode key file %q as standard Base64: %w", path, err)
	}
	if len(raw) != keySize {
		return key, fmt.Errorf("key file %q decodes to %d bytes, want %d", path, len(raw), keySize)
	}
	copy(key[:], raw)
	if key == ([keySize]byte{}) {
		return [keySize]byte{}, fmt.Errorf("key file %q contains an all-zero key", path)
	}
	return key, nil
}
