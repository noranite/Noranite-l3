# Noranite

[English](README.md) · [Русский](README.ru.md) 

[Usage scripts](USAGE.md)

Noranite is an anti-censorship L3 tunnel over UDP designed without exposed protocol framing.

**The Noranite UDP payload is random-looking from the first byte onward.** There are no exposed magic bytes, protocol version, packet type, session ID, sequence number, or recognizable handshake header.

Noranite does not disguise itself as QUIC, DNS, HTTPS, or another allowed protocol. Instead, it avoids fixed content signatures of its own. A censor that wants to identify it selectively must therefore rely on endpoint information, flow-level behavior, statistical classification, or broader filtering rather than a fixed byte signature.

## Core idea

A conventional encrypted protocol often looks roughly like this:

```text
magic
version
packet type
session id
counter
...
encrypted payload
```

The payload may be perfectly encrypted, but the clear-text framing already gives DPI a ready-made signature.

Noranite has no such header.

```text
+-------------------+------------------------------+
| opaque route      | opaque / encrypted payload   |
| 16 bytes          |                              |
+-------------------+------------------------------+
```

The first 16 bytes carry masked data required to locate the session and validate the sequence number. The actual values never appear on the wire.

The rest of the packet likewise contains no exposed message type or other constant structure.

DATA, control packets, and handshake traffic become distinguishable only after cryptographic processing.

## Why "binary noise" matters

The point is not randomness for its own sake. The point is to remove a cheap, precise content signature. A fixed magic value, clear-text type field, or recognizable handshake gives content-based DPI a direct rule to match. Noranite deliberately provides no such rule.

This design belongs to the family of fully encrypted, or "looks like random", transports studied in [*How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic* (USENIX Security 2023)](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi). That work is also a useful warning: random-looking traffic is not automatically unclassifiable. The GFW mechanism characterized there used heuristics over the first TCP payload rather than a protocol-specific signature.

For the mechanism measured in that 2023 study, UDP was not affected: a UDP datagram with a random payload did not trigger blocking. That is an observation about a particular deployed censorship system, not a general property of UDP. [*Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China* (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib) later showed that the GFW performs stateful analysis of QUIC over UDP, including decrypting QUIC Initial packets and applying protocol-specific rules.

Without a fixed content signature, a censor can still use endpoint information, packet sizes, timing, direction, burst structure, traffic volume, or statistical classification. Noranite does not try to eliminate those signals.

Noranite is an L3 tunnel, so unrelated application flows are naturally multiplexed into one outer UDP flow. That interleaving disturbs packet-size, timing, and direction patterns; DATA also adds 0..15 bytes of random authenticated padding. [*Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes* (USENIX Security 2024)](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting) found stream multiplexing to be a viable mitigation against this class of traffic analysis, while also showing that multiplexing and random padding alone do not eliminate flow-level fingerprints.

The broader trade-off is studied from another angle in [*Censorship Evasion with Unidentified Protocol Generation* (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/wails): when an encrypted protocol cannot be identified precisely at the protocol level, blocking unidentified traffic risks collateral damage to other encrypted protocols.

Noranite does not prevent blocking. It removes the cheap case: a fixed protocol signature. Selective identification must instead rely on endpoint information, flow-level analysis, or broader filtering policy.

## Cryptography

A session is established with:

```text
Noise_IK_25519_ChaChaPoly_BLAKE2s
```

Noise IK gives Noranite:

- mutual authentication between client and server;
- static X25519 identities;
- forward secrecy through ephemeral X25519;
- fresh, independent keys for every new connection.

After the handshake, traffic is protected with ChaCha20-Poly1305.

Traffic keys are separated by direction. A new handshake produces a new independent set of keys.

Noise is used only for authentication and key derivation. The Noranite wire format remains a separate layer.

## `K_route`

In addition to Noise identities, a server deployment and its clients share a 32-byte secret called `K_route`.

It is not a traffic-encryption key and it is not a Noise PSK.

`K_route` exists to hide packet structure **before** the receiver has identified the relevant session and can use its traffic key.

It is used to mask:

- `session_id || sequence` in the first 16 bytes of a packet;
- the ephemeral X25519 public key inside the Noise handshake.

The mask is bound to the individual packet, so identical internal values do not produce identical bytes on the wire.

Knowing `K_route` alone does not allow an attacker to decrypt DATA or recover Noise private keys. Compromising `K_route` does not break the tunnel's cryptographic confidentiality or authentication, but it removes the wire-masking layer for that deployment. In the normal deployment model, `K_route` is provisioned together with the server endpoint, so compromise of a client configuration normally reveals both. At that point traffic analysis is unnecessary; blocking the IP is cheaper.

## Handshake

A standard Noise IK handshake exposes the ephemeral X25519 public key. That is already a sufficiently structured value to contribute to a fingerprint.

Noranite additionally masks it with keyed BLAKE2s using `K_route`.

The handshake also uses random padding and variable packet sizes.

As a result, the recognizable Noise IK structure is absent from the wire:

```text
opaque INIT  ->
             <-  opaque RESPONSE
```

Static identities are authenticated inside Noise.

The server exposes no banner, protocol identifier, or other information that can identify it through an ordinary UDP probe.

A random UDP datagram does not trigger a valid protocol response.

## DATA

One DATA packet carries one IPv4 packet.

The following values are never exposed in clear text on the wire:

- DATA packet type;
- session ID;
- sequence number;
- inner source address;
- inner destination address;
- transport protocol of the inner packet.

The entire inner IPv4 packet is carried inside ChaCha20-Poly1305 ciphertext.

Random authenticated padding is added to each packet, so identical inner packets do not have to produce identical outer sizes.

DATA and control traffic use the same opaque envelope. Their type exists only inside the encrypted portion.

## Replay protection

Every session has its own monotonic sequence number and its own replay window.

The sequence number participates in AEAD nonce construction and is never reused within a session.

A received packet cannot affect tunnel state until it has successfully passed all checks:

```text
route
  ↓
candidate session
  ↓
AEAD authentication
  ↓
replay protection
  ↓
accepted packet
```

Forging an opaque route value is not useful by itself: the real session ID is not an authentication mechanism.

## Cryptographic security model

Traffic confidentiality and authentication do not depend on wire-format masking.

Even if wire masking is treated as completely compromised, traffic protection still rests on standard cryptographic primitives:

- Noise IK for mutual authentication and key agreement;
- X25519 for Diffie-Hellman;
- ChaCha20-Poly1305 for authenticated encryption;
- BLAKE2s inside Noise and for wire masking;
- independent keys for each traffic direction;
- fresh key material for new sessions;
- monotonic nonces;
- replay protection.

`K_route` controls **what the protocol looks like on the wire**.

Noise and ChaCha20-Poly1305 control **whether the traffic can be trusted and whether it can be decrypted**.

These are separate jobs with separate cryptographic boundaries.

## What DPI sees

Without `K_route`, packet contents expose no fixed byte pattern to ordinary content-based DPI.

The wire format contains no exposed:

- protocol magic;
- version;
- packet type;
- client ID;
- session ID;
- packet counter;
- inner IPv4 header;
- Noise static public key;
- Noise ephemeral public key;
- constant handshake header.

Handshake packets have variable sizes and random padding.

DATA packets use per-packet padding.

Control traffic uses the same encrypted envelope.

In other words, there is no useful rule of the form:

```text
if udp[offset:n] == known_constant:
    protocol = Noranite
```

There is no such `known_constant` in the protocol.

## Active probing

Noranite has no unauthenticated discovery protocol.

An arbitrary UDP packet does not produce a recognizable server response.

A valid handshake requires:

- knowledge of `K_route`;
- correct opaque framing;
- a valid Noise IK exchange;
- an authorized client identity.

That rules out the simple discovery model:

```text
send probe
receive VPN banner
block endpoint
```

## Scope

Noranite is a small point-to-point L3 protocol.

The current version uses:

```text
inner network:    IPv4
outer transport:  IPv4 / UDP
topology:         client <-> server
payload mapping:  one IPv4 packet per UDP datagram
```

Noranite is not trying to be a universal VPN framework, a protocol impersonation system, or a complete defense against traffic analysis.

It solves one problem directly:

**Noranite carries authenticated, encrypted L3 traffic in a wire format that gives a passive observer no simple way to identify it as Noranite.**
