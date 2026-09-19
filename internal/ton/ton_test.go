package ton

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
)

func TestPointerRejectsZeroDeadlineAndBadHeader(t *testing.T) {
	for _, p := range [][]byte{make([]byte, PointerSize), append([]byte{2, 0}, make([]byte, PointerSize-2)...), append([]byte{1, 1}, make([]byte, PointerSize-2)...)} {
		if _, err := EncodeComment(p); err == nil {
			t.Fatalf("accepted invalid pointer header/deadline: %x", p[:2])
		}
	}
}

func TestPointerSerializationIsExactAndStrict(t *testing.T) {
	p := make([]byte, 74)
	p[0] = PointerVersion
	p[66] = 7
	text, err := EncodeComment(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseComment(text)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(p) {
		t.Fatal("pointer changed")
	}
	if _, err := ParseComment(text + "x"); err == nil {
		t.Fatal("accepted trailing data")
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"wrong length":  func(q []byte) []byte { return append(q, 0) },
		"wrong version": func(q []byte) []byte { q[0] = 2; return q },
		"reserved byte": func(q []byte) []byte { q[1] = 1; return q },
		"zero deadline": func(q []byte) []byte {
			for i := 66; i < len(q); i++ {
				q[i] = 0
			}
			return q
		},
	} {
		t.Run(name, func(t *testing.T) {
			q := mutate(append([]byte(nil), p...))
			if _, err := ParseComment(base64.StdEncoding.EncodeToString(q)); err == nil {
				t.Fatal("accepted non-canonical pointer")
			}
		})
	}
}

func TestListFiltersAddressAndCarriesComments(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"transactions":[{"hash":"h","account":{"address":"me"},"utime":3,"in_msg":{"source":"src","message":"` + commentForTest() + `"}},{"hash":"x","account":{"address":"other"},"in_msg":{"message":"` + commentForTest() + `"}}]}`))
	}))
	defer s.Close()
	b := New(Config{Address: "me", Network: "mainnet", BaseURL: s.URL, PostPath: "/send", ListPath: "/list", HeightPath: "/height", HTTPClient: s.Client()})
	got, err := b.ListIncoming(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].TxID != "h" {
		t.Fatalf("got %#v", got)
	}
}

func TestHTTPHonorsCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	b := New(Config{Address: "me", Network: "mainnet", BaseURL: s.URL, PostPath: "/send", ListPath: "/list", HeightPath: "/height", HTTPClient: s.Client()})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := b.Height(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func commentForTest() string {
	p := make([]byte, 74)
	p[0] = PointerVersion
	p[66] = 7
	s, _ := EncodeComment(p)
	return s
}

var _ chain.Chain = (*Backend)(nil)
