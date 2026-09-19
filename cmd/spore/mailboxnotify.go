package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/notify"
)

type mailboxNotifySpec struct {
	Email   string `json:"email,omitempty"`
	SMS     string `json:"sms,omitempty"`
	Webhook string `json:"webhook,omitempty"`
}

// mailboxNotifyConfig is deliberately non-secret. Provider passwords/tokens
// are loaded from SPORE_NOTIFY_* environment variables by notify.NewFromEnv.
func writeMailboxNotifyConfig(path, user string, spec mailboxNotifySpec) error {
	cfg, err := loadMailboxNotifyConfig(path)
	if err != nil {
		return err
	}
	cfg[user] = spec
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func parseEnvPort(name string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return fallback
	}
	return n
}

func loadMailboxNotifyConfig(path string) (map[string]mailboxNotifySpec, error) {
	if path == "" {
		return map[string]mailboxNotifySpec{}, nil
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]mailboxNotifySpec{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("notify config: read: %w", err)
	}
	var cfg map[string]mailboxNotifySpec
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("notify config: JSON: %w", err)
	}
	if cfg == nil {
		cfg = map[string]mailboxNotifySpec{}
	}
	return cfg, nil
}

func buildMailboxNotifiers(path string, names []string, common notify.Options) (map[string]*notify.Outbox, error) {
	cfg, err := loadMailboxNotifyConfig(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*notify.Outbox)
	for _, name := range names {
		spec := cfg[name]
		o := common
		o.EmailTo = spec.Email
		o.SMSTo = spec.SMS
		o.WebhookURL = spec.Webhook
		if spec.Email == "" {
			o.SMTPHost, o.SMTPPort, o.SMTPFrom, o.SMTPUsername = "", 0, "", ""
		}
		if spec.SMS == "" {
			o.TwilioSID, o.TwilioFrom = "", ""
		}
		if spec.Webhook == "" {
			o.WebhookToken = ""
		}
		d, err := notify.NewFromEnv(o)
		if err != nil {
			return nil, fmt.Errorf("notify config user %q: %w", name, err)
		}
		if spec.Email == "" && spec.SMS == "" && spec.Webhook == "" {
			continue
		}
		queue := filepath.Join(filepath.Dir(path), "outbox", name+".jsonl")
		q, err := notify.NewOutbox(queue, d, 30*time.Second)
		if err != nil {
			return nil, fmt.Errorf("notify outbox user %q: %w", name, err)
		}
		out[name] = q
	}
	return out, nil
}

// notifyBodyPut emits a durable arrival alert after the authenticated mailbox
// accepts an encrypted body. The alert contains only the body CID, never bytes.
func notifyBodyPut(next http.Handler, q *notify.Outbox) http.Handler {
	if q == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isBodyPut := r.Method == http.MethodPut &&
			(strings.HasPrefix(r.URL.Path, "/put/") || strings.HasPrefix(r.URL.Path, "/body/"))
		if !isBodyPut {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusResponseWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status >= 200 && sw.status < 300 {
			id := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
			if err := q.Enqueue(notify.Event{TxID: id, Subject: "Spore private message pending", Received: time.Now()}); err != nil {
				log.Printf("mailbox notification queue: %v", err)
			}
		}
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}
