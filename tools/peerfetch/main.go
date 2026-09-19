// peerfetch — tiny diagnostic client for the spore-peer transport (WIRE_SPEC
// §5): fetch a body by CID from any spore-peer serve node and verify it.
//
//	go run ./tools/peerfetch <host:port> <64-hex-cid>
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/liqdmetal/spore/internal/peerstore"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: peerfetch <host:port> <64-hex-cid>")
		os.Exit(2)
	}
	addr, cidHex := os.Args[1], os.Args[2]
	var cid [32]byte
	if len(cidHex) != 64 {
		fmt.Fprintln(os.Stderr, "cid must be 64 hex chars")
		os.Exit(2)
	}
	for i := 0; i < 32; i++ {
		var v byte
		fmt.Sscanf(cidHex[2*i:2*i+2], "%02x", &v)
		cid[i] = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	body, err := peerstore.Fetch(ctx, addr, cid)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetch:", err)
		os.Exit(1)
	}
	fmt.Printf("fetched %d bytes, sha256 verified == %s\n", len(body), cidHex)
}
