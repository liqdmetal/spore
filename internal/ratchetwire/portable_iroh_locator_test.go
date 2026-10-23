package ratchetwire

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

type portableLocatorStore struct {
	local   map[[32]byte][]byte
	network map[[32]byte][]byte
	locator [32]byte
	used    [32]byte
}

func (s *portableLocatorStore) Put(cid [32]byte, body []byte, _ time.Time) error {
	s.local[cid] = append([]byte(nil), body...)
	return nil
}
func (s *portableLocatorStore) PutWithLocator(cid [32]byte, body []byte, _ time.Time) ([32]byte, error) {
	if sha256.Sum256(body) != cid {
		return [32]byte{}, ErrBadFrame
	}
	s.local[cid] = append([]byte(nil), body...)
	s.network[s.locator] = append([]byte(nil), body...)
	return s.locator, nil
}
func (s *portableLocatorStore) Get(cid [32]byte) ([]byte, error) {
	body, ok := s.local[cid]
	if !ok {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), body...), nil
}
func (s *portableLocatorStore) GetWithLocator(_ [32]byte, locator [32]byte) ([]byte, error) {
	s.used = locator
	body, ok := s.network[locator]
	if !ok {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), body...), nil
}
func (s *portableLocatorStore) Delete(cid [32]byte) error {
	if _, ok := s.local[cid]; !ok {
		return store.ErrNotFound
	}
	delete(s.local, cid)
	return nil
}
func (s *portableLocatorStore) Reap(time.Time) int { return 0 }
func (s *portableLocatorStore) Len() int           { return len(s.local) }

func portableTestFrame(t *testing.T) Frame {
	t.Helper()
	aliceID, bobID := filled(0x31), filled(0x32)
	spk, opkPriv := filled(0x33), filled(0x34)
	var opk [32]byte
	copy(opk[:], opkPriv)
	bundle, err := ratchet.BuildBundle(bobID, spk, 1, &opk, 2)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := secure.SigPubOf(bobID)
	if err != nil {
		t.Fatal(err)
	}
	alice, hs, err := ratchet.EstablishInitiator(aliceID, bundle, pinned)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := alice.Encrypt([]byte("portable Iroh locator test"))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := NewInitFrame(hs, msg, time.Now().Add(time.Hour).Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestPortableIrohLocatorRoundTripsAcrossCodecsAndFetches(t *testing.T) {
	locator := [32]byte{0xA7, 0x91}
	network := make(map[[32]byte][]byte)
	sender := &portableLocatorStore{local: make(map[[32]byte][]byte), network: network, locator: locator}
	ptr, err := PutFrame(sender, portableTestFrame(t))
	if err != nil {
		t.Fatal(err)
	}
	if !ptr.HasIrohHash || ptr.IrohHash != locator {
		t.Fatalf("sender pointer omitted Iroh locator: %#v", ptr)
	}

	payload := PayloadForPointer(ptr)
	raw := payload.MarshalBinary()
	parsed, err := ParsePointerPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != PointerV2 || parsed.Pointer() != ptr {
		t.Fatalf("binary pointer round-trip: %#v", parsed)
	}
	if _, err := ParsePointerPayload(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated v2 pointer accepted")
	}

	for name, codec := range map[string]ChainPayloadCodec{
		"canonical": CanonicalChainCodec{},
		"dero":      DeroChainCodec{},
		"json":      JSONCodec{},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := codec.EncodePointer(parsed)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := codec.DecodePointer(encoded)
			if !ok {
				t.Fatalf("codec decode failed: %#v", got)
			}
			if name == "dero" {
				gotPtr := got.Pointer()
				if !gotPtr.RouteOmitted || !gotPtr.HasIrohHash || gotPtr.IrohHash != ptr.IrohHash || gotPtr.CID != ptr.CID {
					t.Fatalf("compact DERO V2 pointer lost locator/CID: %#v", gotPtr)
				}
			} else if got.Pointer() != ptr {
				t.Fatalf("codec round-trip: %#v, want %#v", got.Pointer(), ptr)
			}
		})
	}
	if _, err := (XMRChainCodec{}).EncodePointer(parsed); err != ErrCarrierUnsupported {
		t.Fatalf("XMR must continue refusing the oversized pointer: %v", err)
	}

	receiver := &portableLocatorStore{local: make(map[[32]byte][]byte), network: network}
	got, err := FetchFrame(receiver, parsed.Pointer(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != FrameInit || receiver.used != locator {
		t.Fatalf("remote locator not used: kind=%d locator=%x", got.Kind, receiver.used)
	}
}

func TestDeroPortableIrohPointerFitsPayload0AndFetches(t *testing.T) {
	locator := [32]byte{0xB7, 0x92}
	network := make(map[[32]byte][]byte)
	sender := &portableLocatorStore{local: make(map[[32]byte][]byte), network: network, locator: locator}
	ptr, err := PutFrame(sender, portableTestFrame(t))
	if err != nil {
		t.Fatal(err)
	}
	codec := DeroChainCodec{}
	encoded, err := codec.EncodePointer(PayloadForPointer(ptr))
	if err != nil {
		t.Fatal(err)
	}
	args, err := dero.PayloadToArgs(encoded)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := dero.PackArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) > dero.Payload0Limit {
		t.Fatalf("DERO V2 pointer is %d bytes, limit %d", len(packed), dero.Payload0Limit)
	}
	decoded, ok := codec.DecodePointer(encoded)
	if !ok || decoded.Version != PointerV2 || !decoded.RouteOmitted || decoded.IrohHash != locator {
		t.Fatalf("compact DERO pointer decode = %#v, %v", decoded, ok)
	}
	receiver := &portableLocatorStore{local: make(map[[32]byte][]byte), network: network}
	frame, err := FetchFrame(receiver, decoded.Pointer(), time.Now())
	if err != nil || frame.Kind != FrameInit {
		t.Fatalf("compact DERO pointer fetch = kind %d, err %v", frame.Kind, err)
	}
}

func TestPortableIrohLocatorStillRequiresSporeSHA256CID(t *testing.T) {
	locator := [32]byte{0xA7, 0x91}
	network := make(map[[32]byte][]byte)
	sender := &portableLocatorStore{local: make(map[[32]byte][]byte), network: network, locator: locator}
	ptr, err := PutFrame(sender, portableTestFrame(t))
	if err != nil {
		t.Fatal(err)
	}
	network[locator] = []byte("wrong ciphertext")
	receiver := &portableLocatorStore{local: make(map[[32]byte][]byte), network: network}
	if _, err := FetchFrame(receiver, ptr, time.Now()); err == nil {
		t.Fatal("tampered remote body passed SHA-256 CID validation")
	}
}

func TestPointerV1WireRemainsByteExact(t *testing.T) {
	p := PointerPayload{Version: PointerV1, BurnDeadline: 123}
	p.Route[0], p.CID[0] = 1, 2
	got := p.MarshalBinary()
	want := make([]byte, 74)
	want[0] = PointerV1
	want[2], want[34] = 1, 2
	want[66] = 123
	if !bytes.Equal(got, want) {
		t.Fatalf("V1 wire changed: %x", got)
	}
}
