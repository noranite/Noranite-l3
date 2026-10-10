package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/noranite/Noranite-l3/internal/noisehandshake"
	"github.com/noranite/Noranite-l3/internal/peerstore"
	"github.com/noranite/Noranite-l3/internal/provisioning"
	"github.com/noranite/Noranite-l3/internal/servercontrol"
)

const defaultPeersFile = "/etc/noranite/server.peers"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "noranite-peer:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: noranite-peer {add|remove} [options]")
	}
	switch args[0] {
	case "add":
		return runAdd(args[1:], stdout, stderr)
	case "remove":
		return runRemove(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runAdd(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("noranite-peer add", flag.ContinueOnError)
	flags.SetOutput(stderr)
	tunnelAddressText := flags.String("tunnel-address", "", "server tunnel address and /16 prefix, e.g. 10.66.0.1/16")
	tunName := flags.String("tun", "nrnt0", "server TUN interface used to verify --tunnel-address")
	privateKeyOut := flags.String("private-key-out", "", "new client private-key file (created mode 0600)")
	publicKeyOut := flags.String("public-key-out", "", "optional new client public-key file")
	peersFile := flags.String("peers-file", defaultPeersFile, "persistent server peer configuration file")
	socket := flags.String("socket", servercontrol.DefaultSocketPath, "server Unix control socket")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *tunnelAddressText == "" || *privateKeyOut == "" {
		return errors.New("usage: noranite-peer add --tunnel-address IP/16 --private-key-out PATH [--public-key-out PATH] [--peers-file PATH] [--socket PATH]")
	}

	tunnelAddress, err := netip.ParsePrefix(*tunnelAddressText)
	if err != nil {
		return fmt.Errorf("parse tunnel address: %w", err)
	}
	if err := provisioning.ValidateTunnelAddress(tunnelAddress); err != nil {
		return err
	}
	if err := validateTunnelAddressMatchesInterface(*tunName, tunnelAddress); err != nil {
		return err
	}

	persistentPeers, err := peerstore.Load(*peersFile)
	if err != nil {
		return fmt.Errorf("load persistent peers: %w", err)
	}
	response, err := servercontrol.Do(*socket, servercontrol.Request{Operation: servercontrol.OperationPeerList})
	if err != nil {
		return fmt.Errorf("list runtime peers: %w", err)
	}
	if !response.OK {
		return fmt.Errorf("list runtime peers: %s", response.Error)
	}

	used := make([]netip.Addr, 0, len(persistentPeers)+len(response.Peers))
	for _, peer := range persistentPeers {
		used = append(used, peer.TunnelIPv4)
	}
	for _, peer := range response.Peers {
		ip, err := netip.ParseAddr(peer.IP)
		if err != nil {
			return fmt.Errorf("parse runtime peer address %q: %w", peer.IP, err)
		}
		used = append(used, ip.Unmap())
	}

	assigned, err := provisioning.AllocateTunnelIPv4(tunnelAddress, used)
	if err != nil {
		return err
	}
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		return err
	}
	if err := writeKeyExclusive(*privateKeyOut, privateKey[:], 0o600); err != nil {
		return err
	}
	cleanupPrivate := true
	defer func() {
		if cleanupPrivate {
			_ = os.Remove(*privateKeyOut)
		}
	}()

	cleanupPublic := false
	if *publicKeyOut != "" {
		if err := writeKeyExclusive(*publicKeyOut, publicKey[:], 0o644); err != nil {
			return err
		}
		cleanupPublic = true
		defer func() {
			if cleanupPublic {
				_ = os.Remove(*publicKeyOut)
			}
		}()
	}

	desired := append([]peerstore.Record(nil), persistentPeers...)
	desired = append(desired, peerstore.Record{TunnelIPv4: assigned, PublicKey: publicKey})
	if err := peerstore.WriteAtomic(*peersFile, desired); err != nil {
		return fmt.Errorf("persist peer: %w", err)
	}

	// server.peers is authoritative after this point. Keep the generated client
	// identity even if the point runtime update needs full reconciliation.
	cleanupPrivate = false
	cleanupPublic = false

	if err := applyRuntimeWithResync(
		*socket,
		servercontrol.Request{
			Operation: servercontrol.OperationPeerSet,
			Peer: &servercontrol.WirePeer{
				IP:        assigned.String(),
				PublicKey: servercontrol.EncodePublicKey(publicKey),
			},
		},
		*peersFile,
		stderr,
	); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "tunnel_ip=%s\n", assigned)
	fmt.Fprintf(stdout, "public_key=%s\n", servercontrol.EncodePublicKey(publicKey))
	fmt.Fprintf(stdout, "private_key_file=%s\n", *privateKeyOut)
	if *publicKeyOut != "" {
		fmt.Fprintf(stdout, "public_key_file=%s\n", *publicKeyOut)
	}
	return nil
}

func runRemove(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("noranite-peer remove", flag.ContinueOnError)
	flags.SetOutput(stderr)
	publicKeyText := flags.String("public-key", "", "client X25519 public key (Base64)")
	peersFile := flags.String("peers-file", defaultPeersFile, "persistent server peer configuration file")
	socket := flags.String("socket", servercontrol.DefaultSocketPath, "server Unix control socket")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *publicKeyText == "" {
		return errors.New("usage: noranite-peer remove --public-key KEY [--peers-file PATH] [--socket PATH]")
	}

	publicKey, err := noisehandshake.ParsePublicKey(*publicKeyText)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	persistentPeers, err := peerstore.Load(*peersFile)
	if err != nil {
		return fmt.Errorf("load persistent peers: %w", err)
	}

	desired := make([]peerstore.Record, 0, len(persistentPeers))
	removed := false
	for _, peer := range persistentPeers {
		if peer.PublicKey == publicKey {
			removed = true
			continue
		}
		desired = append(desired, peer)
	}
	if removed {
		if err := peerstore.WriteAtomic(*peersFile, desired); err != nil {
			return fmt.Errorf("persist peer removal: %w", err)
		}
	}

	if err := applyRuntimeWithResync(
		*socket,
		servercontrol.Request{
			Operation: servercontrol.OperationPeerRemove,
			PublicKey: servercontrol.EncodePublicKey(publicKey),
		},
		*peersFile,
		stderr,
	); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "public_key=%s\n", servercontrol.EncodePublicKey(publicKey))
	fmt.Fprintf(stdout, "removed_from_config=%t\n", removed)
	return nil
}

func applyRuntimeWithResync(
	socket string,
	request servercontrol.Request,
	peersFile string,
	stderr io.Writer,
) error {
	if err := doRuntimeRequest(socket, request); err != nil {
		pointErr := err
		if err := syncRuntimePeersFromFile(socket, peersFile); err != nil {
			return fmt.Errorf("%s failed: %v; peer sync recovery failed: %w", request.Operation, pointErr, err)
		}
		fmt.Fprintf(stderr, "warning: %s failed: %v; recovered with peer sync\n", request.Operation, pointErr)
	}
	return nil
}

func syncRuntimePeersFromFile(socket, path string) error {
	peers, err := peerstore.Load(path)
	if err != nil {
		return fmt.Errorf("load persistent peers: %w", err)
	}
	wirePeers := make([]servercontrol.WirePeer, 0, len(peers))
	for _, peer := range peers {
		wirePeers = append(wirePeers, servercontrol.WirePeer{
			IP:        peer.TunnelIPv4.String(),
			PublicKey: servercontrol.EncodePublicKey(peer.PublicKey),
		})
	}
	return doRuntimeRequest(socket, servercontrol.Request{
		Operation: servercontrol.OperationPeerSync,
		Peers:     &wirePeers,
	})
}

func doRuntimeRequest(socket string, request servercontrol.Request) error {
	response, err := servercontrol.Do(socket, request)
	if err != nil {
		return err
	}
	if !response.OK {
		return errors.New(response.Error)
	}
	return nil
}

func validateTunnelAddressMatchesInterface(interfaceName string, expected netip.Prefix) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("look up tunnel interface %q: %w", interfaceName, err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("list addresses on tunnel interface %q: %w", interfaceName, err)
	}
	if tunnelAddressMatches(expected, addresses) {
		return nil
	}

	actualIPv4 := make([]string, 0, len(addresses))
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil || !prefix.Addr().Unmap().Is4() {
			continue
		}
		actualIPv4 = append(actualIPv4, prefix.String())
	}
	actual := "no IPv4 address"
	if len(actualIPv4) != 0 {
		actual = strings.Join(actualIPv4, ", ")
	}
	return fmt.Errorf(
		"--tunnel-address %s does not match tunnel interface %s (%s)",
		expected,
		interfaceName,
		actual,
	)
}

func tunnelAddressMatches(expected netip.Prefix, addresses []net.Addr) bool {
	expectedAddr := expected.Addr().Unmap()
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		if prefix.Bits() == expected.Bits() && prefix.Addr().Unmap() == expectedAddr {
			return true
		}
	}
	return false
}

func generateKeyPair() (noisehandshake.PrivateKey, noisehandshake.PublicKey, error) {
	var privateKey noisehandshake.PrivateKey
	for {
		if _, err := rand.Read(privateKey[:]); err != nil {
			return noisehandshake.PrivateKey{}, noisehandshake.PublicKey{}, fmt.Errorf("generate private key: %w", err)
		}
		var nonZero byte
		for _, value := range privateKey {
			nonZero |= value
		}
		if nonZero != 0 {
			break
		}
	}
	publicKey, err := noisehandshake.PublicKeyFromPrivate(privateKey)
	if err != nil {
		return noisehandshake.PrivateKey{}, noisehandshake.PublicKey{}, err
	}
	return privateKey, publicKey, nil
}

func writeKeyExclusive(path string, key []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create key file %q: %w", path, err)
	}
	text := base64.StdEncoding.EncodeToString(key) + "\n"
	if _, err := io.WriteString(file, text); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write key file %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close key file %q: %w", path, err)
	}
	return nil
}
