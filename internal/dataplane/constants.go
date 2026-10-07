package dataplane

const (
	// RouteSize is the opaque routing header size in bytes.
	RouteSize = 16

	// TagSize is the ChaCha20-Poly1305 authentication tag size in bytes.
	TagSize = 16

	// NonceSize is the IETF ChaCha20-Poly1305 nonce size in bytes.
	NonceSize = 12

	// ReferenceTunnelMTU is the default Opaque-L3 v1 TUN MTU.
	//
	// With maximum DATA padding, the complete outer IPv4 packet is:
	//
	//	1380 inner IPv4
	//	  15 DATA padding
	//	  32 Opaque-L3
	//	   8 UDP
	//	  20 outer IPv4
	//	----------------
	//	1455 bytes
	//
	// This is an operational default, not a wire compatibility parameter.
	ReferenceTunnelMTU = 1380

	// ReplayWindowSize is the receive replay window size.
	ReplayWindowSize = 4096

	// DataOverhead is the fixed DATA overhead excluding outer UDP/IPv4 headers.
	DataOverhead = RouteSize + TagSize

	// MaxDataPadding is the maximum authenticated padding after the inner IPv4
	// packet. Values 0..15 can be selected uniformly with a 0x0f mask while the
	// reference MTU remains below a 1500-byte outer IPv4 packet.
	MaxDataPadding = 15

	// MaxDataExpansion is the maximum growth of an inner IPv4 packet in the UDP payload:
	//
	//	16 opaque_route
	//	15 DATA padding
	//	16 Poly1305 tag
	//	----------------
	//	47 bytes maximum
	//
	// The fixed protocol overhead remains DataOverhead == 32.
	MaxDataExpansion = DataOverhead + MaxDataPadding

	// MinTunnelMTU is the minimum size of an inner IPv4 header without options.
	MinTunnelMTU = 20

	// MaxTunnelMTU is the largest inner IPv4 packet that can always fit into
	// one IPv4 UDP payload after worst-case Opaque-L3 DATA expansion.
	//
	// IPv4 total length is limited to 65535 bytes. Subtracting the 20-byte
	// outer IPv4 header and 8-byte UDP header leaves 65507 bytes of UDP
	// payload. Opaque-L3 DATA may add up to MaxDataExpansion bytes, therefore:
	//
	//	65535 - 20 - 8 - 47 = 65460
	//
	// This is an absolute protocol/runtime bound for the current IPv4/UDP
	// outer transport, not a recommended operational MTU.
	MaxTunnelMTU = 65535 - 20 - 8 - MaxDataExpansion

	// MinWirePacketSize is the smallest cryptographically processable envelope:
	// a 16-byte route, at least one plaintext byte, and a 16-byte tag. Semantic
	// DATA or CONTROL validation happens after authentication.
	MinWirePacketSize = RouteSize + 1 + TagSize

	// MinGeneratedEstablishmentWirePacketSize and
	// MaxGeneratedEstablishmentWirePacketSize are sender-side traffic-shaping
	// bounds for the generated establishment exchange and its activation
	// CONTROL. They are not receiver compatibility limits.
	MinGeneratedEstablishmentWirePacketSize = 384
	MaxGeneratedEstablishmentWirePacketSize = 1200
)

const (
	// routeMaskDomain is the domain separator fixed by the wire specification.
	routeMaskDomain = "opaque-l3/v1/route-mask"

	// establishmentEphemeralMaskDomain separates the outer obfuscation of the
	// cleartext Noise ephemeral public key from the route-mask PRF.
	establishmentEphemeralMaskDomain = "opaque-l3/v1/establishment-e-mask"
)
