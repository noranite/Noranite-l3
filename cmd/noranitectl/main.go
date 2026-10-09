package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/noranite/Noranite-l3/internal/servercontrol"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "noranitectl:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	root := flag.NewFlagSet("noranitectl", flag.ContinueOnError)
	root.SetOutput(stderr)
	socket := root.String("socket", servercontrol.DefaultSocketPath, "Unix control socket")
	if err := root.Parse(args); err != nil {
		return err
	}
	args = root.Args()
	if len(args) < 2 || args[0] != "peer" {
		return errors.New("usage: noranitectl [-socket path] peer {list|set|remove} [options]")
	}

	switch args[1] {
	case "list":
		if len(args) != 2 {
			return errors.New("usage: noranitectl [-socket path] peer list")
		}
		response, err := servercontrol.Do(*socket, servercontrol.Request{Operation: servercontrol.OperationPeerList})
		if err != nil {
			return err
		}
		if !response.OK {
			return errors.New(response.Error)
		}
		w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "IP\tPUBLIC KEY")
		for _, peer := range response.Peers {
			_, _ = fmt.Fprintf(w, "%s\t%s\n", peer.IP, peer.PublicKey)
		}
		return w.Flush()

	case "set":
		flags := flag.NewFlagSet("peer set", flag.ContinueOnError)
		flags.SetOutput(stderr)
		ip := flags.String("ip", "", "tunnel IPv4")
		publicKey := flags.String("public-key", "", "client X25519 public key (Base64)")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *ip == "" || *publicKey == "" {
			return errors.New("usage: noranitectl [-socket path] peer set --ip IP --public-key KEY")
		}
		response, err := servercontrol.Do(*socket, servercontrol.Request{
			Operation: servercontrol.OperationPeerSet,
			Peer: &servercontrol.WirePeer{
				IP:        *ip,
				PublicKey: *publicKey,
			},
		})
		if err != nil {
			return err
		}
		if !response.OK {
			return errors.New(response.Error)
		}
		return nil

	case "remove":
		flags := flag.NewFlagSet("peer remove", flag.ContinueOnError)
		flags.SetOutput(stderr)
		publicKey := flags.String("public-key", "", "client X25519 public key (Base64)")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *publicKey == "" {
			return errors.New("usage: noranitectl [-socket path] peer remove --public-key KEY")
		}
		response, err := servercontrol.Do(*socket, servercontrol.Request{
			Operation: servercontrol.OperationPeerRemove,
			PublicKey: *publicKey,
		})
		if err != nil {
			return err
		}
		if !response.OK {
			return errors.New(response.Error)
		}
		return nil

	default:
		return fmt.Errorf("unknown peer command %q", args[1])
	}
}
