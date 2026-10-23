package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/liqdmetal/spore/internal/peerstore"
	"github.com/liqdmetal/spore/internal/store"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "spore-peer:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: spore-peer <version|serve|fetch> [flags]")
	}
	switch args[0] {
	case "version":
		fmt.Printf("spore-peer %s (E2 direct-body transport)\n", version)
		return nil
	case "serve":
		return serve(args[1:])
	case "fetch":
		return fetch(args[1:])
	default:
		return fmt.Errorf("unknown command %q (use version, serve, or fetch)", args[0])
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "127.0.0.1:8099", "TCP listen address (default loopback; use a trusted LAN/VPN for remote peers)")
	dir := fs.String("dir", "", "disk body-store directory; must match the sender's -store disk:// directory")
	storeDir := fs.String("store-dir", "", "alias for -dir")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: spore-peer serve --dir <body-store> [--listen 127.0.0.1:8099]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("serve: unexpected positional arguments")
	}
	if *dir != "" && *storeDir != "" && filepath.Clean(*dir) != filepath.Clean(*storeDir) {
		return errors.New("serve: --dir and --store-dir disagree")
	}
	bodyDir := *dir
	if bodyDir == "" {
		bodyDir = *storeDir
	}
	if bodyDir == "" {
		return errors.New("serve requires --dir (or --store-dir)")
	}

	bodyStore, err := store.NewDiskStore(filepath.Clean(bodyDir))
	if err != nil {
		return fmt.Errorf("open body store: %w", err)
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	fmt.Printf("LISTEN %s\n", listener.Addr().String())
	fmt.Fprintln(os.Stderr, "spore-peer: unauthenticated direct TCP; peers see this endpoint and fetch timing; serve E2 ciphertext only and restrict remote access to a trusted LAN/VPN")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return peerstore.Serve(ctx, listener, bodyStore)
}

func fetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "", "peer host:port")
	cidText := fs.String("cid", "", "64-hex SHA-256 body CID")
	out := fs.String("out", "", "output path (created with mode 0600; existing files are not overwritten)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("fetch: unexpected positional arguments")
	}
	if *addr == "" || *cidText == "" || *out == "" {
		return errors.New("fetch requires --addr, --cid, and --out")
	}
	cidBytes, err := hex.DecodeString(*cidText)
	if err != nil || len(cidBytes) != 32 {
		return errors.New("fetch: cid must be exactly 64 hexadecimal characters")
	}
	var cid [32]byte
	copy(cid[:], cidBytes)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	body, err := peerstore.Fetch(ctx, *addr, cid)
	if err != nil {
		return err
	}
	dir := filepath.Dir(*out)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("fetch: create output directory: %w", err)
	}
	outFile, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("fetch: create output without overwrite: %w", err)
	}
	complete := false
	defer func() {
		_ = outFile.Close()
		if !complete {
			_ = os.Remove(*out)
		}
	}()
	if _, err := outFile.Write(body); err != nil {
		return fmt.Errorf("fetch: write output: %w", err)
	}
	if err := outFile.Sync(); err != nil {
		return fmt.Errorf("fetch: sync output: %w", err)
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("fetch: close output: %w", err)
	}
	complete = true
	return nil
}
