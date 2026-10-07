package establishment

// RoutingDomainMaterial is long-lived material used before traffic Session
// selection. Its lifetime is independent from any traffic generation.
type RoutingDomainMaterial struct {
	RouteKey [32]byte
}
