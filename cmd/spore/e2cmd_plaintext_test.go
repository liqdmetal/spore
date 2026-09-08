package main

import (
	"bytes"
	"os"
	"testing"
)

func TestReadPlaintextFromFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "msg-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("hello e2\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got, err := readPlaintext(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello e2" {
		t.Fatalf("got %q, want %q", got, "hello e2")
	}
}

func TestReadPlaintextFromStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	go func() {
		w.Write([]byte("from stdin"))
		w.Close()
	}()
	got, err := readPlaintext("")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from stdin" {
		t.Fatalf("got %q, want %q", got, "from stdin")
	}
}

func TestReadPlaintextDashIsStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	go func() {
		w.Write([]byte("dash stdin"))
		w.Close()
	}()
	got, err := readPlaintext("-")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("dash stdin")) {
		t.Fatalf("got %q, want %q", got, "dash stdin")
	}
}
