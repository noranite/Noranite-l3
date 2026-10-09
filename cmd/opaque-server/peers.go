package main

import "github.com/noranite/Noranite-l3/internal/peerstore"

type peerSpec = peerstore.Record

func loadPeerSpecs(path string) ([]peerSpec, error) {
	return peerstore.Load(path)
}
