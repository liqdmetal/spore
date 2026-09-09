package mailbox

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// batchBundle builds a distinct valid bundle with a unique OPK id/pub for
// the single-use batch tests. The crypto fields are placeholder-shaped but
// structurally valid (validatePrekey checks presence/shape, not signature
// validity against a real key — that path is covered in ratchet's own tests).
func batchBundle(opkID uint32) ratchet.SPKBundle {
	var b ratchet.SPKBundle
	b.IKPub[0] = 1
	b.SPKPub[0] = 2
	b.SPKID = 1
	b.SPKSig[0] = 3
	opk := [32]byte{}
	opk[0] = byte(opkID)
	opk[31] = byte(opkID >> 8)
	b.OPKPub = &opk
	b.OPKID = opkID
	b.OPKHash[0] = byte(opkID)
	return b
}

func TestPrekeyBatchServesEachBundleExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	bundles := []ratchet.SPKBundle{batchBundle(1), batchBundle(2), batchBundle(3)}
	if err := m.publishPrekeyBatch(bundles); err != nil {
		t.Fatal(err)
	}
	if got := m.PrekeyBatchLen(); got != 3 {
		t.Fatalf("batch len = %d, want 3", got)
	}

	seen := map[uint32]bool{}
	for i := 0; i < 3; i++ {
		b, ok := m.popPrekey()
		if !ok {
			t.Fatalf("pop %d returned not-ok", i)
		}
		if seen[b.OPKID] {
			t.Fatalf("OPK id %d served twice — single-use violated", b.OPKID)
		}
		seen[b.OPKID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("served %d distinct OPKs, want 3", len(seen))
	}
	// Batch exhausted, no static prekey -> pop fails.
	if _, ok := m.popPrekey(); ok {
		t.Fatal("pop succeeded on exhausted batch with no static prekey")
	}
}

func TestPrekeyBatchFallsBackToStaticWhenExhausted(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.publishPrekeyBatch([]ratchet.SPKBundle{batchBundle(7)}); err != nil {
		t.Fatal(err)
	}
	static := testPrekey() // no OPK (degraded), valid static bundle
	if err := m.publishPrekey(static); err != nil {
		t.Fatal(err)
	}
	// First pop: the batch bundle (OPK id 7).
	b, ok := m.popPrekey()
	if !ok || b.OPKID != 7 {
		t.Fatalf("first pop = %+v ok=%v, want OPKID 7", b, ok)
	}
	// Second pop: batch empty, falls back to the static bundle.
	b2, ok := m.popPrekey()
	if !ok || b2 != static {
		t.Fatalf("fallback pop = %+v ok=%v, want static %+v", b2, ok, static)
	}
	// Static keeps serving (it's the degraded fallback, not single-use).
	if _, ok := m.popPrekey(); !ok {
		t.Fatal("static fallback stopped serving")
	}
}

func TestPrekeyBatchPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.publishPrekeyBatch([]ratchet.SPKBundle{batchBundle(1), batchBundle(2)}); err != nil {
		t.Fatal(err)
	}
	// Consume one; the shrunken batch must be durable.
	if _, ok := m.popPrekey(); !ok {
		t.Fatal("pop failed")
	}
	m2, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := m2.PrekeyBatchLen(); got != 1 {
		t.Fatalf("batch len after restart = %d, want 1 (consumed bundle must NOT resurrect)", got)
	}
	b, ok := m2.popPrekey()
	if !ok || b.OPKID != 2 {
		t.Fatalf("after-restart pop = %+v ok=%v, want OPKID 2", b, ok)
	}
}

func TestPrekeyBatchRejectsDuplicatesAndMissingOPK(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Duplicate OPK id.
	if err := m.publishPrekeyBatch([]ratchet.SPKBundle{batchBundle(1), batchBundle(1)}); err == nil {
		t.Fatal("accepted duplicate OPK ids")
	}
	// A bundle with no OPK in the batch (degraded belongs on static PUT).
	noOPK := batchBundle(5)
	noOPK.OPKPub = nil
	noOPK.OPKID = 0
	if err := m.publishPrekeyBatch([]ratchet.SPKBundle{noOPK}); err == nil {
		t.Fatal("accepted batch bundle with no OPK")
	}
	// Empty batch.
	if err := m.publishPrekeyBatch([]ratchet.SPKBundle{}); err == nil {
		t.Fatal("accepted empty batch")
	}
}

func TestPrekeyBatchHTTPPopIsSingleUse(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.publishPrekeyBatch([]ratchet.SPKBundle{batchBundle(1), batchBundle(2)}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	fetch := func() uint32 {
		resp, err := http.Get(srv.URL + "/prekey")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /prekey = %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		var pb PrekeyBundle
		if err := json.Unmarshal(body, &pb); err != nil {
			t.Fatalf("decode: %v (%s)", err, body)
		}
		if pb.Bundle.OPKPub == nil {
			t.Fatal("served bundle had no OPK")
		}
		return pb.Bundle.OPKID
	}
	a, b := fetch(), fetch()
	if a == b {
		t.Fatalf("two HTTP GETs returned the same OPK id %d — single-use violated", a)
	}
	// Third GET: batch exhausted, no static -> 404.
	resp, err := http.Get(srv.URL + "/prekey")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("exhausted GET /prekey = %d, want 404", resp.StatusCode)
	}
}

func TestPrekeyBatchHTTPUpload(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	payload, _ := json.Marshal(prekeyBatchJSON{Bundles: []ratchet.SPKBundle{batchBundle(1), batchBundle(2)}})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/prekey-batch", strings.NewReader(string(payload)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT /prekey-batch = %d: %s", resp.StatusCode, body)
	}
	if got := m.PrekeyBatchLen(); got != 2 {
		t.Fatalf("batch len after upload = %d, want 2", got)
	}
	// Malformed batch rejected.
	bad, _ := http.NewRequest(http.MethodPut, srv.URL+"/prekey-batch", strings.NewReader(`{"bundles":[{"ik_pub":"nope"}]}`))
	br, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer br.Body.Close()
	if br.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed batch = %d, want 400", br.StatusCode)
	}
}
