package noisehandshake

import (
	"bytes"
	"testing"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/establishment"
)

func TestNoisePrologueBindsExchangeIDLittleEndian(t *testing.T) {
	prologue, err := noisePrologue(0x0102030405060708)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("opaque-l3/establishment/v1"), 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01)
	if !bytes.Equal(prologue, want) {
		t.Fatalf("prologue = %x, want %x", prologue, want)
	}
}

func TestNoiseIKAuthenticatesPeerAndProducesSameTrafficMaterial(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, err := PublicKeyFromPrivate(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}

	const exchangeID = uint64(0x0102030405060708)
	freshness := encodeFreshness(testFreshness(1_700_000_000, 123_456_789))
	const sessionID = uint64(0x1122334455667788)
	responsePayload, err := encodeResponsePayload(sessionID)
	if err != nil {
		t.Fatal(err)
	}

	client, err := newInitiatorHandshake(clientPrivate, serverPublic, exchangeID, bytes.NewReader(testEntropy(0x81)))
	if err != nil {
		t.Fatal(err)
	}
	server, err := newResponderHandshake(serverPrivate, exchangeID, bytes.NewReader(testEntropy(0x41)))
	if err != nil {
		t.Fatal(err)
	}

	initMessage, initCS1, initCS2, err := client.WriteMessage(nil, freshness[:])
	if err != nil {
		t.Fatalf("client WriteMessage: %v", err)
	}
	if initCS1 != nil || initCS2 != nil {
		t.Fatal("IK completed after first message")
	}
	if len(initMessage) != initNoiseMessageSize {
		t.Fatalf("INIT Noise size = %d, want %d", len(initMessage), initNoiseMessageSize)
	}

	serverPayload, _, _, err := server.ReadMessage(nil, initMessage)
	if err != nil {
		t.Fatalf("server ReadMessage: %v", err)
	}
	if !bytes.Equal(serverPayload, freshness[:]) {
		t.Fatalf("server freshness payload = %x, want %x", serverPayload, freshness)
	}
	clientPublic, err := PublicKeyFromPrivate(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authenticatedClient, err := peerStaticPublicKey(server)
	if err != nil {
		t.Fatal(err)
	}
	if authenticatedClient != clientPublic {
		t.Fatalf("authenticated client key = %x, want %x", authenticatedClient, clientPublic)
	}

	responseMessage, serverCS1, serverCS2, err := server.WriteMessage(nil, responsePayload[:])
	if err != nil {
		t.Fatalf("server WriteMessage: %v", err)
	}
	clientPayload, clientCS1, clientCS2, err := client.ReadMessage(nil, responseMessage)
	if err != nil {
		t.Fatalf("client ReadMessage: %v", err)
	}
	if !bytes.Equal(clientPayload, responsePayload[:]) {
		t.Fatalf("client response payload = %x, want %x", clientPayload, responsePayload)
	}

	serverMaterial, err := trafficMaterialFromSplit(sessionID, serverCS1, serverCS2)
	if err != nil {
		t.Fatal(err)
	}
	clientMaterial, err := trafficMaterialFromSplit(sessionID, clientCS1, clientCS2)
	if err != nil {
		t.Fatal(err)
	}
	if serverMaterial != clientMaterial {
		t.Fatalf("split material mismatch:\nserver=%+v\nclient=%+v", serverMaterial, clientMaterial)
	}
}

func TestSplitMappingDecryptsRealDataplanePacketsBothDirections(t *testing.T) {
	material := completeTestHandshake(t)
	clientSession, err := establishmentClientSession(material)
	if err != nil {
		t.Fatal(err)
	}
	serverSession, err := establishmentServerSession(material)
	if err != nil {
		t.Fatal(err)
	}

	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0xa0 + i)
	}
	clientScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatal(err)
	}
	serverScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatal(err)
	}

	assertDataplaneDirection(t, clientSession, clientScratch, serverSession, serverScratch, []byte("client to server"))
	assertDataplaneDirection(t, serverSession, serverScratch, clientSession, clientScratch, []byte("server to client"))
}

func TestExchangeIDIsCryptographicallyBoundByPrologue(t *testing.T) {
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, err := PublicKeyFromPrivate(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	freshness := encodeFreshness(testFreshness(1_700_000_000, 0))

	client, err := newInitiatorHandshake(clientPrivate, serverPublic, 10, bytes.NewReader(testEntropy(0x81)))
	if err != nil {
		t.Fatal(err)
	}
	server, err := newResponderHandshake(serverPrivate, 11, bytes.NewReader(testEntropy(0x41)))
	if err != nil {
		t.Fatal(err)
	}
	message, _, _, err := client.WriteMessage(nil, freshness[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := server.ReadMessage(nil, message); err == nil {
		t.Fatal("Noise accepted INIT under a different exchange_id prologue")
	}
}

func completeTestHandshake(t *testing.T) establishment.TrafficSessionMaterial {
	t.Helper()
	clientPrivate := testPrivateKey(1)
	serverPrivate := testPrivateKey(33)
	serverPublic, err := PublicKeyFromPrivate(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newInitiatorHandshake(clientPrivate, serverPublic, 7, bytes.NewReader(testEntropy(0x81)))
	if err != nil {
		t.Fatal(err)
	}
	server, err := newResponderHandshake(serverPrivate, 7, bytes.NewReader(testEntropy(0x41)))
	if err != nil {
		t.Fatal(err)
	}
	freshness := encodeFreshness(testFreshness(100, 1))
	initMessage, _, _, err := client.WriteMessage(nil, freshness[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := server.ReadMessage(nil, initMessage); err != nil {
		t.Fatal(err)
	}
	payload, err := encodeResponsePayload(99)
	if err != nil {
		t.Fatal(err)
	}
	responseMessage, _, _, err := server.WriteMessage(nil, payload[:])
	if err != nil {
		t.Fatal(err)
	}
	_, cs1, cs2, err := client.ReadMessage(nil, responseMessage)
	if err != nil {
		t.Fatal(err)
	}
	material, err := trafficMaterialFromSplit(99, cs1, cs2)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func establishmentClientSession(material establishment.TrafficSessionMaterial) (*dataplane.Session, error) {
	return establishment.NewClientSession(material)
}

func establishmentServerSession(material establishment.TrafficSessionMaterial) (*dataplane.Session, error) {
	return establishment.NewServerSession(material)
}

func assertDataplaneDirection(
	t *testing.T,
	sender *dataplane.Session,
	senderScratch *dataplane.DataScratch,
	receiver *dataplane.Session,
	receiverScratch *dataplane.DataScratch,
	plaintext []byte,
) {
	t.Helper()
	wire, sequence, err := sender.SealDataToWithPadding(
		senderScratch,
		make([]byte, 0, len(plaintext)+dataplane.MaxDataExpansion),
		plaintext,
		0,
	)
	if err != nil {
		t.Fatalf("SealDataToWithPadding: %v", err)
	}
	packet := append([]byte(nil), wire...)
	opened, err := receiver.AuthenticateInPlace(receiverScratch, packet, sequence)
	if err != nil {
		t.Fatalf("AuthenticateInPlace: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened plaintext = %q, want %q", opened, plaintext)
	}
}

func testEntropy(start byte) []byte {
	entropy := make([]byte, keySize)
	for i := range entropy {
		entropy[i] = start + byte(i)
	}
	return entropy
}
