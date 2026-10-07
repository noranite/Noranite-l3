package prototype

import "github.com/noranite/Noranite-l3/internal/dataplane"

const StaticSessionID uint64 = 0x71a24e9c5312bb19

func StaticRouteKey() [32]byte {
	routeKey, _, _ := staticKeys()
	return routeKey
}

func NewStaticClientSession() (*dataplane.Session, error) {
	_, c2s, s2c := staticKeys()

	sequence, err := RandomPrototypeSequence()
	if err != nil {
		return nil, err
	}

	return dataplane.NewSession(
		StaticSessionID,
		c2s,
		s2c,
		sequence,
	)
}

func NewStaticServerSession() (*dataplane.Session, error) {
	_, c2s, s2c := staticKeys()

	sequence, err := RandomPrototypeSequence()
	if err != nil {
		return nil, err
	}

	return dataplane.NewSession(
		StaticSessionID,
		s2c,
		c2s,
		sequence,
	)
}

func staticKeys() (
	routeKey [32]byte,
	c2s [32]byte,
	s2c [32]byte,
) {
	for i := 0; i < 32; i++ {
		routeKey[i] = byte(i + 1)
		c2s[i] = byte(0x41 + i)
		s2c[i] = byte(0x81 + i)
	}

	return routeKey, c2s, s2c
}
