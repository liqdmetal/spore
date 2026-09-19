package ratchetwire

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// StateProtector encrypts endpoint ratchet state for local storage. The key is
// supplied by the endpoint keystore; this package never derives it from a
// carrier, password, or message metadata.
type StateProtector struct {
	key [32]byte
	mu  sync.Mutex
}

func NewStateProtector(key []byte) (*StateProtector, error) {
	if len(key) != 32 {
		return nil, errors.New("ratchetwire: state key must be 32 bytes")
	}
	var k [32]byte
	copy(k[:], key)
	return &StateProtector{key: k}, nil
}

func (p *StateProtector) Seal(id [8]byte, state []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("ratchetwire: nil state protector")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	aead, err := chacha20poly1305.NewX(p.key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ad := append([]byte("spore/e2/state/v1"), id[:]...)
	ct := aead.Seal(nil, nonce, state, ad)
	out := make([]byte, 0, 4+1+8+len(nonce)+len(ct))
	out = append(out, []byte("S2E1")...)
	out = append(out, byte(len(nonce)))
	out = append(out, id[:]...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func (p *StateProtector) Open(id [8]byte, blob []byte) ([]byte, error) {
	if p == nil || len(blob) < 4+1+8 {
		return nil, errors.New("ratchetwire: malformed protected state")
	}
	if string(blob[:4]) != "S2E1" || blob[4] != chacha20poly1305.NonceSizeX {
		return nil, errors.New("ratchetwire: unsupported protected state")
	}
	var stored [8]byte
	copy(stored[:], blob[5:13])
	if stored != id {
		return nil, errors.New("ratchetwire: state/session mismatch")
	}
	if len(blob) < 13+chacha20poly1305.NonceSizeX {
		return nil, errors.New("ratchetwire: protected state truncated")
	}
	nonce := blob[13 : 13+chacha20poly1305.NonceSizeX]
	ct := blob[13+chacha20poly1305.NonceSizeX:]
	if len(ct) < chacha20poly1305.Overhead {
		return nil, errors.New("ratchetwire: protected state truncated")
	}
	aead, err := chacha20poly1305.NewX(p.key[:])
	if err != nil {
		return nil, err
	}
	ad := append([]byte("spore/e2/state/v1"), id[:]...)
	return aead.Open(nil, nonce, ct, ad)
}

// StateDigest is a non-secret diagnostic commitment used by a local store to
// reject accidental rollback. It is never a decryption key.
func StateDigest(blob []byte) [32]byte { return sha256.Sum256(blob) }

// ProtectedStateFile is a compact authenticated record for one session.
type ProtectedStateFile struct {
	SessionID [8]byte
	Sequence  uint64
	Digest    [32]byte
	Blob      []byte
}

func MarshalProtectedState(s ProtectedStateFile) []byte {
	out := make([]byte, 0, 4+8+8+32+4+len(s.Blob))
	out = append(out, []byte("S2P1")...)
	out = append(out, s.SessionID[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], s.Sequence)
	out = append(out, b8[:]...)
	out = append(out, s.Digest[:]...)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], uint32(len(s.Blob)))
	out = append(out, b4[:]...)
	out = append(out, s.Blob...)
	return out
}

func ParseProtectedState(b []byte) (ProtectedStateFile, error) {
	if len(b) < 4+8+8+32+4 || string(b[:4]) != "S2P1" {
		return ProtectedStateFile{}, errors.New("ratchetwire: bad protected state record")
	}
	var out ProtectedStateFile
	copy(out.SessionID[:], b[4:12])
	out.Sequence = binary.LittleEndian.Uint64(b[12:20])
	copy(out.Digest[:], b[20:52])
	n := int(binary.LittleEndian.Uint32(b[52:56]))
	if n < chacha20poly1305.Overhead || n != len(b)-56 {
		return ProtectedStateFile{}, errors.New("ratchetwire: bad protected state length")
	}
	out.Blob = append([]byte(nil), b[56:]...)
	if StateDigest(out.Blob) != out.Digest {
		return ProtectedStateFile{}, errors.New("ratchetwire: protected state digest mismatch")
	}
	return out, nil
}

func ProtectSession(p *StateProtector, id [8]byte, sequence uint64, state []byte) ([]byte, error) {
	if len(state) == 0 {
		return nil, fmt.Errorf("ratchetwire: empty session state")
	}
	blob, err := p.Seal(id, state)
	if err != nil {
		return nil, err
	}
	return MarshalProtectedState(ProtectedStateFile{SessionID: id, Sequence: sequence, Digest: StateDigest(blob), Blob: blob}), nil
}

func UnprotectSession(p *StateProtector, id [8]byte, record []byte) (uint64, []byte, error) {
	r, err := ParseProtectedState(record)
	if err != nil {
		return 0, nil, err
	}
	if r.SessionID != id {
		return 0, nil, errors.New("ratchetwire: protected state id mismatch")
	}
	state, err := p.Open(id, r.Blob)
	return r.Sequence, state, err
}
