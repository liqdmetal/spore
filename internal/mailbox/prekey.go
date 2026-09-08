package mailbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// PrekeyBundle is the endpoint-local public X3DH bundle. It intentionally
// contains only ratchet.SPKBundle's public fields; private keys never cross
// this API. It is not chain data and is not included in mailbox messages.
type PrekeyBundle struct {
	Bundle ratchet.SPKBundle `json:"bundle"`
}

var errInvalidPrekey = errors.New("mailbox: invalid prekey bundle")

const prekeyFile = "prekey.json"

func validatePrekey(b *ratchet.SPKBundle) error {
	if b == nil || b.IKPub == [32]byte{} || b.SPKPub == [32]byte{} || b.SPKSig == [64]byte{} {
		return errInvalidPrekey
	}
	if b.OPKPub != nil {
		if *b.OPKPub == [32]byte{} {
			return errInvalidPrekey
		}
	} else if b.OPKID != 0 {
		return errInvalidPrekey
	}
	return nil
}

func (m *Mailbox) publishPrekey(b ratchet.SPKBundle) error {
	if err := validatePrekey(&b); err != nil {
		return err
	}
	raw, err := json.Marshal(PrekeyBundle{Bundle: b})
	if err != nil {
		return err
	}

	// Create the temporary file in the mailbox directory so Rename is an
	// atomic replacement on filesystems that support it. CreateTemp starts
	// with restrictive permissions; Chmod also tightens the mode if the
	// process umask is unexpectedly permissive.
	tmp, err := os.CreateTemp(m.dir, prekeyFile+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(m.dir, prekeyFile)); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// Preserve the invariant when replacing a pre-existing file on platforms
	// whose rename keeps the destination's mode.
	if err := os.Chmod(filepath.Join(m.dir, prekeyFile), 0o600); err != nil {
		return err
	}

	m.prekeyMu.Lock()
	m.prekey = &b
	m.prekeyMu.Unlock()
	return nil
}

func loadPrekey(dir string) (*ratchet.SPKBundle, error) {
	raw, err := os.ReadFile(filepath.Join(dir, prekeyFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p PrekeyBundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || dec.Decode(&struct{}{}) != io.EOF || validatePrekey(&p.Bundle) != nil {
		return nil, errInvalidPrekey
	}
	return &p.Bundle, nil
}

func (m *Mailbox) currentPrekey() (ratchet.SPKBundle, bool) {
	m.prekeyMu.RLock()
	defer m.prekeyMu.RUnlock()
	if m.prekey == nil {
		return ratchet.SPKBundle{}, false
	}
	return *m.prekey, true
}

func (m *Mailbox) handlePrekey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		var p PrekeyBundle
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil || dec.Decode(&struct{}{}) != io.EOF || validatePrekey(&p.Bundle) != nil {
			http.Error(w, "invalid prekey bundle", http.StatusBadRequest)
			return
		}
		if err := m.publishPrekey(p.Bundle); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		b, ok := m.currentPrekey()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PrekeyBundle{Bundle: b})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
