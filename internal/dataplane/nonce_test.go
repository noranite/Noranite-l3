package dataplane

import (
	"encoding/hex"
	"testing"
)

func TestNonceFromSequence(t *testing.T) {
	tests := []struct {
		name     string
		sequence uint64
		wantHex  string
	}{
		{name: "zero", sequence: 0, wantHex: "000000000000000000000000"},
		{name: "one", sequence: 1, wantHex: "000000000100000000000000"},
		{name: "byte order", sequence: 0x0102030405060708, wantHex: "000000000807060504030201"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce := nonceFromSequence(tt.sequence)
			if got := hex.EncodeToString(nonce[:]); got != tt.wantHex {
				t.Fatalf("nonce = %s, want %s", got, tt.wantHex)
			}
		})
	}
}
