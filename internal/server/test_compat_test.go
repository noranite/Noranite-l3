package server

import "github.com/noranite/Noranite-l3/internal/dataplane"

// Test-only aliases keep the pre-refactor server tests focused on behavior while
// production code gets the new package boundary. These aliases are not compiled
// into non-test binaries.
type (
	Session      = dataplane.Session
	DataScratch  = dataplane.DataScratch
	IPv4Header   = dataplane.IPv4Header
	ServerConfig = Config
	ServerCore   = Core
)

const (
	RouteSize         = dataplane.RouteSize
	TagSize           = dataplane.TagSize
	NonceSize         = dataplane.NonceSize
	ReplayWindowSize  = dataplane.ReplayWindowSize
	DataOverhead      = dataplane.DataOverhead
	MaxDataPadding    = dataplane.MaxDataPadding
	MaxDataExpansion  = dataplane.MaxDataExpansion
	MinWirePacketSize = dataplane.MinWirePacketSize
)

var (
	ErrPacketTooShort    = dataplane.ErrPacketTooShort
	ErrPacketTooLarge    = dataplane.ErrPacketTooLarge
	ErrBufferTooSmall    = dataplane.ErrBufferTooSmall
	ErrAuthentication    = dataplane.ErrAuthentication
	ErrReplay            = dataplane.ErrReplay
	ErrInvalidIPv4       = dataplane.ErrInvalidIPv4
	ErrSequenceExhausted = dataplane.ErrSequenceExhausted
	ErrInvalidConfig     = dataplane.ErrInvalidConfig
	ErrInvalidPadding    = dataplane.ErrInvalidPadding
)

func NewSession(
	id uint64,
	txKey, rxKey [32]byte,
	initialTxSequence uint64,
) (*Session, error) {
	return dataplane.NewSession(id, txKey, rxKey, initialTxSequence)
}

func NewServerCore(config ServerConfig) (*ServerCore, error) {
	return New(config)
}

func NewDataScratch(routeKey [32]byte) (*DataScratch, error) {
	return dataplane.NewDataScratch(routeKey)
}

func ParseIPv4(packet []byte) (IPv4Header, error) {
	return dataplane.ParseIPv4(packet)
}

func decodePacketRoute(
	scratch *DataScratch,
	packet []byte,
) (sessionID, sequence uint64, err error) {
	route, err := dataplane.DecodeRoute(scratch, packet)
	if err != nil {
		return 0, 0, err
	}
	return route.SessionID, route.Sequence, nil
}
