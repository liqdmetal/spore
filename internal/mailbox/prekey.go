package mailbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

// PublishPrekey publishes our own public X3DH bundle for GET /prekey
// discovery. Public keys only — validation rejects any bundle with private
// material or missing signatures. Exported for the CLI (mailbox prekey
// subcommand and mailbox run's identity flags); internal callers use
// publishPrekey directly.
func (m *Mailbox) PublishPrekey(b ratchet.SPKBundle) error {
	return m.publishPrekey(b)
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

// Prekey batch: N pre-signed PUBLIC bundles (each with a distinct OPK),
// generated offline by the owner and uploaded to the mailbox. GET /prekey
// pops and removes ONE bundle per request, so no two senders ever receive
// the same OPK — the mailbox serves single-use prekeys without ever holding
// a private key. When the batch is exhausted, GET /prekey falls back to the
// static bundle (degraded/no-OPK if that's what it is) or 404.
const prekeyBatchFile = "prekey-batch.json"

// maxPrekeyBatch bounds an uploaded batch (~500B/bundle JSON: 1000 ≈ 500KB).
const maxPrekeyBatch = 1000

type prekeyBatchJSON struct {
	Bundles []ratchet.SPKBundle `json:"bundles"`
}

func (m *Mailbox) publishPrekeyBatch(bundles []ratchet.SPKBundle) error {
	if len(bundles) == 0 {
		return errors.New("mailbox: empty prekey batch")
	}
	if len(bundles) > maxPrekeyBatch {
		return fmt.Errorf("mailbox: prekey batch too large (%d > %d)", len(bundles), maxPrekeyBatch)
	}
	seenOPK := map[uint32]bool{}
	seenSPK := map[uint32]bool{}
	for i := range bundles {
		if err := validatePrekey(&bundles[i]); err != nil {
			return fmt.Errorf("mailbox: bundle %d invalid: %w", i, err)
		}
		// Every bundle must carry a DISTINCT OPK, or two senders could still
		// collide after a pop. Bundles without OPK are only acceptable as a
		// single trailing degraded entry — reject mixed/duplicate degraded.
		if bundles[i].OPKPub == nil {
			return fmt.Errorf("mailbox: batch bundle %d has no OPK (degraded bundles must be published via PUT /prekey, not the batch)", i)
		}
		if seenOPK[bundles[i].OPKID] {
			return fmt.Errorf("mailbox: duplicate OPK id %d in batch", bundles[i].OPKID)
		}
		seenOPK[bundles[i].OPKID] = true
		if !seenSPK[bundles[i].SPKID] {
			seenSPK[bundles[i].SPKID] = true
		}
	}
	raw, err := json.Marshal(prekeyBatchJSON{Bundles: bundles})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(m.dir, prekeyBatchFile+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(m.dir, prekeyBatchFile)); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	m.prekeyMu.Lock()
	m.batch = append([]ratchet.SPKBundle(nil), bundles...)
	m.prekeyMu.Unlock()
	return nil
}

// popPrekey removes and returns the FIRST batch bundle (durable removal
// before return, same fail-safe order as the OPK pool: a crash after
// persist loses one bundle forever but can never serve it twice). Falls
// back to the static bundle when the batch is empty; ok=false only when
// neither exists.
func (m *Mailbox) popPrekey() (ratchet.SPKBundle, bool) {
	m.prekeyMu.Lock()
	defer m.prekeyMu.Unlock()
	if len(m.batch) > 0 {
		b := m.batch[0]
		m.batch = m.batch[1:]
		// Persist the shrunken batch BEFORE releasing the lock/returning:
		// the bundle is single-use the instant it is handed out.
		if err := writePrekeyBatch(m.dir, m.batch); err != nil {
			// Restore on failure: better to risk re-serving (same behavior
			// as the pre-batch static model) than to lose the whole batch.
			m.batch = append([]ratchet.SPKBundle{b}, m.batch...)
			return ratchet.SPKBundle{}, false
		}
		return b, true
	}
	if m.prekey != nil {
		return *m.prekey, true
	}
	return ratchet.SPKBundle{}, false
}

func writePrekeyBatch(dir string, bundles []ratchet.SPKBundle) error {
	raw, err := json.Marshal(prekeyBatchJSON{Bundles: bundles})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, prekeyBatchFile+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, prekeyBatchFile)); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func loadPrekeyBatch(dir string) ([]ratchet.SPKBundle, error) {
	raw, err := os.ReadFile(filepath.Join(dir, prekeyBatchFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f prekeyBatchJSON
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		return nil, errInvalidPrekey
	}
	for i := range f.Bundles {
		if err := validatePrekey(&f.Bundles[i]); err != nil || f.Bundles[i].OPKPub == nil {
			return nil, errInvalidPrekey
		}
	}
	return f.Bundles, nil
}

// PrekeyBatchLen reports how many single-use bundles remain queued.
func (m *Mailbox) PrekeyBatchLen() int {
	m.prekeyMu.RLock()
	defer m.prekeyMu.RUnlock()
	return len(m.batch)
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
		// Pop one single-use bundle when a batch is queued: two senders
		// fetching concurrently can never receive the same OPK. Falls back
		// to the static bundle when the batch is exhausted.
		b, ok := m.popPrekey()
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

// handlePrekeyBatch accepts the owner's upload of N pre-signed public
// bundles (PUT /prekey-batch). Body cap: ~1000 bundles ≈ 500KB JSON.
func (m *Mailbox) handlePrekeyBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var f prekeyBatchJSON
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid prekey batch", http.StatusBadRequest)
		return
	}
	if err := m.publishPrekeyBatch(f.Bundles); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
