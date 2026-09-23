package derosim

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ServeHandler wraps a Sim with the debug routes the soak driver uses:
//
//	GET  /debug/state  -> the full observable State snapshot
//	POST /debug/bump   -> {"blocks": N} advance the simulated height
//
// Wallet RPCs live under /w/<route>/json_rpc (Handler()).
func ServeHandler(s *Sim) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/debug/state", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.State())
	}))
	mux.Handle("/debug/bump", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var p struct {
			Blocks uint64 `json:"blocks"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Blocks == 0 || p.Blocks > 1_000_000 {
			http.Error(w, "body must be {\"blocks\": N}", http.StatusBadRequest)
			return
		}
		s.Bump(p.Blocks)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]uint64{"height": func() uint64 { st := s.State(); return st.Height }()})
	}))
	mux.Handle("/w/", s.Handler())
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"ok": "derosim"})
			return
		}
		http.NotFound(w, r)
	}))
	return mux
}

// Routes describes the endpoints a driver needs to point parties at.
func (s *Sim) Routes(listen string) map[string]string {
	st := s.State()
	out := map[string]string{
		"state": "http://" + listen + "/debug/state",
		"bump":  "http://" + listen + "/debug/bump",
	}
	for name := range st.Addresses {
		out[name] = "http://" + listen + "/w/" + name
	}
	return out
}

// WalletRoute is the URL prefix for a party's wallet RPC.
func WalletRoute(base, party string) string {
	return strings.TrimRight(base, "/") + "/w/" + party
}
