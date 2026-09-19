package credits

// Package credits implements PREPAID ANONYMOUS CREDITS: paid usage that the
// operator cannot link to a user.
//
// THE PROBLEM
//
// Per-message billing normally requires the operator to COUNT each user's
// messages. That rebuilds the exact per-user activity log a private mailbox
// exists to destroy: "we bill per message" means "we log your message count and
// timing". Metering is a privacy regression, not a pricing detail.
//
// THE CONSTRUCTION
//
// A credit is a one-time bearer token. The user generates a random secret,
// commits to it, and the issuer signs the COMMITMENT at purchase time. Later
// the user spends the credit by revealing the secret. The issuer verifies its
// own signature and records the spend, but the spend carries NO identity: it is
// just a random value the issuer has never seen before.
//
// Purchase and spend are unlinkable in the *bookkeeping*: what the issuer holds
// after a purchase is a signature over a hash it cannot connect to the secret
// revealed later, because the secret was never disclosed at purchase.
//
// HONEST LIMITS — READ THESE BEFORE CALLING IT ANONYMOUS
//
//  1. This is a HASH-COMMITMENT scheme, NOT a blind signature. The issuer signs
//     H(secret), so at purchase it learns that hash. If it stores it, it can
//     later link a spend to the purchase that produced it. Unlinkability here
//     is POLICY (the issuer discards the commitment after signing), not
//     mathematics. A true blind signature (RSA-BSSA, or a VOPRF like
//     Privacy Pass) removes that trust; this deliberately does not pretend to.
//  2. Batch purchases are linkable to each other by timing/quantity, so buy
//     credits in standard batch sizes, well before spending them.
//  3. Network metadata is unaffected: credits hide WHO is paying, not who is
//     connecting. Tor/relay handles that layer.
//
// It is implemented this way because it is small, auditable, and dependency
// free while still removing the per-user counter — the concrete privacy harm.
// The upgrade path to blind signatures is confined to Issue/Redeem.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	domain     = "spore/credit/v1"
	secretSize = 32
)

// Credit is what a user holds: a secret plus the issuer's signature over its
// commitment. It is a BEARER instrument — whoever holds it can spend it, so it
// must be stored as securely as money.
type Credit struct {
	Domain string `json:"domain"`
	// Secret is the random preimage, revealed only at spend time.
	Secret string `json:"secret"`
	// Denom is what this credit buys (e.g. "msg", "body-1mb", "permanent").
	// It is signed, so a 1-message credit cannot be spent as a permanent-body
	// credit.
	Denom string `json:"denom"`
	// IssuerPub is the hex Ed25519 key that signed the commitment.
	IssuerPub string `json:"issuer_pub"`
	// Sig is the issuer's signature over (domain, denom, commitment).
	Sig string `json:"sig"`
}

// commitment is H(domain || denom || secret): what the issuer signs, and what
// it can verify again at spend time.
func commitment(denom string, secret []byte) []byte {
	h := sha256.New()
	put := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	put([]byte(domain))
	put([]byte(denom))
	put(secret)
	return h.Sum(nil)
}

// signedPayload is the exact byte string the issuer signs.
func signedPayload(denom string, commit []byte) []byte {
	var out []byte
	put := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		out = append(out, n[:]...)
		out = append(out, b...)
	}
	put([]byte(domain + "/sig"))
	put([]byte(denom))
	put(commit)
	return out
}

// Request is what a buyer sends to purchase one credit: only a commitment. The
// secret never leaves the buyer, which is what makes the spend unlinkable to
// anything the issuer saw at purchase.
type Request struct {
	Domain     string `json:"domain"`
	Denom      string `json:"denom"`
	Commitment string `json:"commitment"`
}

// NewRequest generates a fresh secret and its purchase request. The caller MUST
// keep the returned secret: without it the credit is unspendable.
func NewRequest(denom string) (secret []byte, req *Request, err error) {
	if denom == "" {
		return nil, nil, errors.New("credits: denom is required")
	}
	secret = make([]byte, secretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, err
	}
	return secret, &Request{
		Domain:     domain,
		Denom:      denom,
		Commitment: hex.EncodeToString(commitment(denom, secret)),
	}, nil
}

// Issue signs a purchase request. The issuer does this AFTER payment settles.
//
// The issuer never learns the secret here, so it cannot spend the credit itself
// and cannot recognise the eventual spend — provided it does not retain the
// commitment (see limit 1 in the package docs).
func Issue(issuer ed25519.PrivateKey, req *Request) (*Credit, error) {
	if len(issuer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("credits: bad issuer key length %d", len(issuer))
	}
	if req == nil {
		return nil, errors.New("credits: nil request")
	}
	if req.Domain != domain {
		return nil, fmt.Errorf("credits: unknown domain %q (want %q)", req.Domain, domain)
	}
	if req.Denom == "" {
		return nil, errors.New("credits: request has no denom")
	}
	commit, err := hex.DecodeString(req.Commitment)
	if err != nil || len(commit) != sha256.Size {
		return nil, errors.New("credits: commitment must be a 32-byte hex hash")
	}
	sig := ed25519.Sign(issuer, signedPayload(req.Denom, commit))
	return &Credit{
		Domain:    domain,
		Secret:    "", // filled in by the buyer, never by the issuer
		Denom:     req.Denom,
		IssuerPub: hex.EncodeToString(issuer.Public().(ed25519.PublicKey)),
		Sig:       hex.EncodeToString(sig),
	}, nil
}

// Finalize attaches the buyer's secret to the issued credit, producing the
// spendable bearer token. It also verifies the issuer actually signed THIS
// secret's commitment, so a malicious issuer cannot hand back a signature for
// a different credit.
func Finalize(c *Credit, secret []byte) (*Credit, error) {
	if c == nil {
		return nil, errors.New("credits: nil credit")
	}
	if len(secret) != secretSize {
		return nil, fmt.Errorf("credits: secret must be %d bytes", secretSize)
	}
	out := *c
	out.Secret = hex.EncodeToString(secret)
	if err := out.Verify(); err != nil {
		return nil, fmt.Errorf("credits: issuer did not sign our commitment: %w", err)
	}
	return &out, nil
}

// Verify checks the issuer's signature over this credit's own commitment. It
// proves the credit is genuine; it says NOTHING about whether it was already
// spent (that is the Ledger's job).
func (c *Credit) Verify() error {
	if c == nil {
		return errors.New("credits: nil credit")
	}
	if c.Domain != domain {
		return fmt.Errorf("credits: unknown domain %q", c.Domain)
	}
	secret, err := hex.DecodeString(c.Secret)
	if err != nil || len(secret) != secretSize {
		return errors.New("credits: bad secret")
	}
	pub, err := hex.DecodeString(c.IssuerPub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("credits: bad issuer_pub")
	}
	sig, err := hex.DecodeString(c.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("credits: bad sig")
	}
	if c.Denom == "" {
		return errors.New("credits: credit has no denom")
	}
	commit := commitment(c.Denom, secret)
	if !ed25519.Verify(ed25519.PublicKey(pub), signedPayload(c.Denom, commit), sig) {
		return errors.New("credits: INVALID credit (not signed by this issuer, or altered)")
	}
	return nil
}

// SpendID is the value a ledger records: H(commitment). Recording the hash
// rather than the secret means a leaked ledger does not hand an attacker
// spendable secrets, and it still detects double-spends exactly.
func (c *Credit) SpendID() (string, error) {
	secret, err := hex.DecodeString(c.Secret)
	if err != nil || len(secret) != secretSize {
		return "", errors.New("credits: bad secret")
	}
	h := sha256.Sum256(commitment(c.Denom, secret))
	return hex.EncodeToString(h[:]), nil
}

// Ledger records spent credits so each is usable exactly once.
//
// It stores ONLY spend ids, a denom, and a coarse day bucket — never a user, an
// IP, a message, or an exact timestamp. That is the whole point: the operator
// can prove a credit was consumed and still cannot reconstruct who did what.
type Ledger struct {
	mu    sync.Mutex
	path  string
	spent map[string]entry
}

type entry struct {
	Denom string `json:"denom"`
	// Day is a UTC date (YYYY-MM-DD), deliberately coarse. An exact timestamp
	// would let an operator correlate a spend with a connection.
	Day string `json:"day"`
}

// OpenLedger loads or creates a ledger at path.
func OpenLedger(path string) (*Ledger, error) {
	l := &Ledger{path: path, spent: map[string]entry{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &l.spent); err != nil {
			return nil, fmt.Errorf("credits: ledger %s is corrupt: %w", path, err)
		}
	}
	return l, nil
}

// Redeem verifies a credit, checks the expected denom, and records the spend.
//
// It returns an error if the credit is invalid, the denom is wrong, or it was
// already spent. Callers must FAIL CLOSED: no service on any error.
func (l *Ledger) Redeem(c *Credit, issuerPub, wantDenom string, now time.Time) error {
	if err := c.Verify(); err != nil {
		return err
	}
	if issuerPub == "" {
		return errors.New("credits: no expected issuer key supplied")
	}
	// Constant time: the issuer key is public, but comparing this way keeps the
	// habit consistent across the codebase.
	if subtle.ConstantTimeCompare([]byte(c.IssuerPub), []byte(issuerPub)) != 1 {
		return fmt.Errorf("credits: credit issued by %s, not by this service (%s)", c.IssuerPub, issuerPub)
	}
	if wantDenom != "" && c.Denom != wantDenom {
		return fmt.Errorf("credits: this is a %q credit but %q is required", c.Denom, wantDenom)
	}
	id, err := c.SpendID()
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, dup := l.spent[id]; dup {
		return errors.New("credits: ALREADY SPENT (a credit is valid exactly once)")
	}
	l.spent[id] = entry{Denom: c.Denom, Day: now.UTC().Format("2006-01-02")}
	return l.saveLocked()
}

// saveLocked persists atomically: temp file, then rename. A crash mid-write
// must never leave a truncated ledger, because a lost spend record is a
// double-spend.
func (l *Ledger) saveLocked() error {
	blob, err := json.Marshal(l.spent)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(l.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// Count returns how many credits have been spent.
func (l *Ledger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.spent)
}

// Revenue reports spends per denom per day — the ONLY accounting an operator
// needs. It supports "how much did we sell" without supporting "what did user X
// do", which is exactly the line this design draws.
func (l *Ledger) Revenue() map[string]map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]map[string]int{}
	for _, e := range l.spent {
		if out[e.Denom] == nil {
			out[e.Denom] = map[string]int{}
		}
		out[e.Denom][e.Day]++
	}
	return out
}

// Prune drops spend records older than the retention window.
//
// Pruning is a privacy REQUIREMENT, not housekeeping: an unbounded ledger is a
// permanent record of activity volume. The trade is explicit — a pruned credit
// could in principle be replayed, so retention must exceed any credit's usable
// lifetime. Callers should expire credits well inside the window.
func (l *Ledger) Prune(before time.Time) int {
	cutoff := before.UTC().Format("2006-01-02")
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for id, e := range l.spent {
		if e.Day < cutoff {
			delete(l.spent, id)
			n++
		}
	}
	if n > 0 {
		_ = l.saveLocked()
	}
	return n
}

// Denoms lists the denominations seen in the ledger, sorted.
func (l *Ledger) Denoms() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	seen := map[string]bool{}
	for _, e := range l.spent {
		seen[e.Denom] = true
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
