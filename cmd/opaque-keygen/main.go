package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/noranite/Noranite-l3/internal/noisehandshake"
)

func main() {
	privateOut := flag.String("private-out", "", "write standard-Base64 private key to this file")
	publicOut := flag.String("public-out", "", "write standard-Base64 public key to this file")
	flag.Parse()

	var private noisehandshake.PrivateKey
	for {
		if _, err := rand.Read(private[:]); err != nil {
			log.Fatalf("generate private key: %v", err)
		}
		var nonZero byte
		for _, value := range private {
			nonZero |= value
		}
		if nonZero != 0 {
			break
		}
	}
	public, err := noisehandshake.PublicKeyFromPrivate(private)
	if err != nil {
		log.Fatalf("derive public key: %v", err)
	}

	privateText := base64.StdEncoding.EncodeToString(private[:])
	publicText := base64.StdEncoding.EncodeToString(public[:])

	if *privateOut != "" {
		if err := os.WriteFile(*privateOut, []byte(privateText+"\n"), 0o600); err != nil {
			log.Fatalf("write private key: %v", err)
		}
	}
	if *publicOut != "" {
		if err := os.WriteFile(*publicOut, []byte(publicText+"\n"), 0o644); err != nil {
			log.Fatalf("write public key: %v", err)
		}
	}

	fmt.Printf("private=%s\npublic=%s\n", privateText, publicText)
}
