// Package dataplane implements the reusable Opaque-L3 v1 DATA plane.
//
// The package owns wire DATA encoding/decoding, route masking, AEAD sequence
// handling, replay state, authenticated endpoint learning and minimal IPv4
// grammar. It deliberately knows nothing about client/server process topology,
// UDP sockets, TUN devices, Noise handshakes or peer/session selection policy.
package dataplane
