package channel

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// NewServer wraps a Box as an HTTP relay. Routes:
//
//	POST /line    {channel,sender,private,data}  -> assigns seq+ts
//	GET  /lines?channel=X&after=N               -> []Line
//	POST /presence {channel,addr}                -> heartbeat
//	GET  /online?channel=X                       -> []string
func NewServer(b *Box) http.Handler {
	return WithCORS(BoxRoutes(b))
}

// boxRoutes builds the route mux without CORS (used by WithCORS and webchat).
func BoxRoutes(b *Box) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /line", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Channel string `json:"channel"`
			Sender  string `json:"sender"`
			Private bool   `json:"private"`
			Data    []byte `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Channel == "" || req.Sender == "" {
			http.Error(w, "channel and sender required", http.StatusBadRequest)
			return
		}
		ln := b.Post(req.Channel, req.Sender, req.Private, req.Data)
		writeJSON(w, ln)
	})

	mux.HandleFunc("GET /lines", func(w http.ResponseWriter, r *http.Request) {
		ch := r.URL.Query().Get("channel")
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		writeJSON(w, b.Poll(ch, after))
	})

	mux.HandleFunc("POST /presence", func(w http.ResponseWriter, r *http.Request) {
		var p Presence
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if p.Addr == "" {
			http.Error(w, "addr required", http.StatusBadRequest)
			return
		}
		ch := p.Channel
		if ch == "" {
			ch = r.URL.Query().Get("channel")
		}
		b.Heartbeat(ch, p.Addr)
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /online", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, b.Online(r.URL.Query().Get("channel")))
	})

	return mux
}

// WithCORS wraps a handler so a browser page served from any origin can call
// the JSON API (POST bodies + the GET endpoints) directly.
func WithCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
