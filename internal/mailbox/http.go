package mailbox

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/liqdmetal/mycelium/internal/crypto"
	"github.com/liqdmetal/mycelium/internal/store"
)

// maxBodyBytes caps a /put body. Bodies are content-addressed ciphertext
// (XChaCha20 output); a realistic envelope is a few KB. 64 MiB is generous
// headroom and bounds the memory a single request can force us to read and
// hash. A var (not const) so tests can shrink it.
var maxBodyBytes = 64 << 20

// Handler returns the HTTP surface for a mailbox:
//
//	PUT    /put/{cidhex}     body = raw ciphertext, X-Burn-Deadline: unix sec
//	                          (sender pushes the body so the mailbox holds it
//	                          before/without the pointer arriving; the body is
//	                          verified to hash to cid). 200 ok | 400 bad cid |
//	                          400 body sha256 != cid.
//	GET    /body/{cidhex}     200 body | 404 not found | 410 expired (peer pull)
//	DELETE /body/{cidhex}     remove a stored body
//	GET    /list              JSON array of decrypted messages (newest first)
//	GET    /get/{cid-or-txid} JSON single message | 404
func (m *Mailbox) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasPrefix(path, "/put/"):
			cid, ok := parseCID(w, strings.TrimPrefix(path, "/put/"))
			if !ok {
				return
			}
			m.handlePut(w, r, cid)
		case strings.HasPrefix(path, "/body/"):
			cid, ok := parseCID(w, strings.TrimPrefix(path, "/body/"))
			if !ok {
				return
			}
			m.handleBody(w, r, cid)
		case path == "/list":
			m.handleList(w, r)
		case strings.HasPrefix(path, "/get/"):
			m.handleGet(w, strings.TrimPrefix(path, "/get/"))
		default:
			http.NotFound(w, r)
		}
	})
}

func parseCID(w http.ResponseWriter, hexcid string) ([32]byte, bool) {
	raw, err := hex.DecodeString(hexcid)
	if err != nil || len(raw) != 32 {
		http.Error(w, "bad cid", http.StatusBadRequest)
		return [32]byte{}, false
	}
	var cid [32]byte
	copy(cid[:], raw)
	return cid, true
}

// handlePut stores a sender-pushed ciphertext body. Content-addressed: the
// body must hash to the requested cid or it is rejected (400), so a sender can
// never plant a wrong body under a cid the recipient's pointer will reference.
func (m *Mailbox) handlePut(w http.ResponseWriter, r *http.Request, cid [32]byte) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(&io.LimitedReader{R: r.Body, N: int64(maxBodyBytes) + 1})
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	if len(body) > maxBodyBytes {
		// Oversized body: reject explicitly instead of silently truncating a
		// too-long body and hashing only its prefix. The old LimitReader+1 read
		// would misreport an oversized body as a CID mismatch (400) and was
		// ambiguous about what the real cap was.
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if crypto.CID(body) != cid {
		http.Error(w, "body sha256 != cid", http.StatusBadRequest)
		return
	}
	deadline := time.Time{}
	if hdr := r.Header.Get("X-Burn-Deadline"); hdr != "" {
		if sec, err := strconv.ParseInt(hdr, 10, 64); err == nil {
			deadline = time.Unix(sec, 0)
		}
	}
	if err := m.st.Put(cid, body, deadline); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (m *Mailbox) handleBody(w http.ResponseWriter, r *http.Request, cid [32]byte) {
	switch r.Method {
	case http.MethodGet:
		body, err := m.st.Get(cid)
		switch err {
		case nil:
			_, _ = w.Write(body)
		case store.ErrNotFound:
			http.NotFound(w, r)
		case store.ErrExpired:
			http.Error(w, "expired", http.StatusGone)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case http.MethodDelete:
		if err := m.st.Delete(cid); err != nil && err != store.ErrNotFound {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Mailbox) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	msgs, err := m.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(msgs)
}

func (m *Mailbox) handleGet(w http.ResponseWriter, id string) {
	msg, err := m.Get(id)
	if err == store.ErrNotFound {
		http.NotFound(w, nil)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(msg)
}
