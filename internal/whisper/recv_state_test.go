package whisper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/dero"
)

// entryJSON renders one R153 transfer entry the wallet would return, in the
// exact wire shape get_transfers emits (payload_rpc as typed arguments).
func entryJSON(height int, txid, text string) map[string]any {
	return map[string]any{
		"height":     height,
		"topoheight": height,
		"txid":       txid,
		"sender":     "s-" + txid,
		"amount":     1,
		"tpos":       0,
		"pos":        0,
		"payload_rpc": []map[string]any{
			{"name": "T", "datatype": "S", "value": text},
			{"name": "W", "datatype": "U", "value": 1393},
		},
	}
}

// fakeWallet serves get_transfers with R153 min_height semantics (>= filter):
// it returns every entry whose height is at least the requested min_height.
type fakeWallet struct {
	mu      sync.Mutex
	entries []map[string]any
	srv     *httptest.Server
}

func newFakeWallet(entries ...map[string]any) *fakeWallet {
	f := &fakeWallet{entries: entries}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				MinHeight float64 `json:"min_height"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		mn := uint64(req.Params.MinHeight)

		f.mu.Lock()
		var out []map[string]any
		for _, e := range f.entries {
			if h, _ := e["height"].(int); uint64(h) >= mn {
				out = append(out, e)
			}
		}
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": "0",
			"result": map[string]any{"entries": out},
		})
	}))
	return f
}

func (f *fakeWallet) add(e map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, e)
}

func (f *fakeWallet) close() { f.srv.Close() }

// recvOne reads one message with a timeout.
func recvOne(t *testing.T, ctx context.Context, ch <-chan Msg) Msg {
	t.Helper()
	select {
	case m, ok := <-ch:
		if !ok {
			t.Fatal("recv channel closed before a message arrived")
		}
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a message")
		return Msg{}
	}
}

// waitCursor polls the state file until Cursor reaches want.
func waitCursor(t *testing.T, path string, want uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := LoadRecvState(path); err == nil && st != nil && st.Cursor == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state cursor never reached %d", want)
}

// The regression this guards: whisper recv used to hardcode minHeight=0 and
// keep its dedup map in memory, so EVERY restart re-delivered the wallet's
// whole history. With a -state file, a restart must resume from the committed
// cursor and skip every already-delivered identity.
func TestRecvStateNoReplayAcrossRestart(t *testing.T) {
	wallet := newFakeWallet(
		entryJSON(5, "tx5", "hi"),
		entryJSON(7, "tx7", "newer"),
	)
	defer wallet.close()
	statePath := filepath.Join(t.TempDir(), "recv.state")
	client := dero.NewClient(wallet.srv.URL, "", "")

	// --- run 1: first ever start, no state. Both historical whispers deliver.
	ctx1, cancel1 := context.WithCancel(context.Background())
	ch1, _ := Recv(ctx1, client, 0, 5*time.Millisecond, statePath)
	if got := recvOne(t, ctx1, ch1); got.Text != "hi" {
		t.Fatalf("run1 first msg = %q", got.Text)
	}
	if got := recvOne(t, ctx1, ch1); got.Text != "newer" {
		t.Fatalf("run1 second msg = %q", got.Text)
	}
	waitCursor(t, statePath, 7)
	cancel1()
	<-ch1

	// --- run 2: restart with the same state file. Nothing may re-deliver.
	ctx2, cancel2 := context.WithCancel(context.Background())
	ch2, _ := Recv(ctx2, client, 0, 5*time.Millisecond, statePath)
	select {
	case m := <-ch2:
		cancel2()
		t.Fatalf("restart re-delivered already-seen message %q", m.Text)
	case <-time.After(300 * time.Millisecond):
		// 60 polls at 5ms with nothing delivered — clean.
	}
	cancel2()
	<-ch2

	// --- run 3: a NEW message arrives after the resume; it must deliver once.
	wallet.add(entryJSON(9, "tx9", "after-resume"))
	ctx3, cancel3 := context.WithCancel(context.Background())
	ch3, _ := Recv(ctx3, client, 0, 5*time.Millisecond, statePath)
	if got := recvOne(t, ctx3, ch3); got.Text != "after-resume" {
		t.Fatalf("run3 msg = %q", got.Text)
	}
	// And it must NOT deliver a second time while the run continues.
	select {
	case m := <-ch3:
		cancel3()
		t.Fatalf("delivered %q twice in one run", m.Text)
	case <-time.After(200 * time.Millisecond):
	}
	waitCursor(t, statePath, 9)
	cancel3()
	<-ch3

	// --- final state: cursor 9, exactly three delivered identities.
	st, err := LoadRecvState(statePath)
	if err != nil || st == nil {
		t.Fatalf("final state: %v", err)
	}
	if st.Cursor != 9 || len(st.Seen) != 3 {
		t.Fatalf("final state = %#v (want cursor 9, 3 seen)", st)
	}
}

// With no state path the old ephemeral behavior stays: the run is still
// deduped in memory, it just does not survive a restart.
func TestRecvEphemeralWithoutState(t *testing.T) {
	wallet := newFakeWallet(entryJSON(5, "tx5", "hi"))
	defer wallet.close()
	client := dero.NewClient(wallet.srv.URL, "", "")

	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := Recv(ctx, client, 0, 5*time.Millisecond, "")
	if got := recvOne(t, ctx, ch); got.Text != "hi" {
		t.Fatalf("msg = %q", got.Text)
	}
	select {
	case m := <-ch:
		t.Fatalf("delivered %q twice in one run", m.Text)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	<-ch
}
