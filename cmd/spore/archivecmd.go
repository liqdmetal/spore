package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/store"
)

// spore archive — mirror issue bodies across several INDEPENDENT substrates so
// a back-catalogue survives any one of them dying.
//
//	spore archive put   -file BODY [-ipfs URL] [-dir D] [-ttl 0]
//	spore archive get   -cid HEX  -out F [-ipfs URL] [-dir D]
//	spore archive check -cid HEX  [-ipfs URL] [-dir D]
//	spore archive health [-ipfs URL] [-dir D]
//
// WHY NOT JUST IPFS: pinning to ONE node is a single point of failure with
// extra steps. If that node dies and nobody else pinned the CID, the body is
// gone. Durability comes from diversity — the same invariant RelayOS's
// substrate fabric is built on: infrastructure may disappear, commitments and
// verifiable evidence must survive.
//
// Integrity is checked LOCALLY on every read: a body is accepted only if
// sha256(body) == the CID asked for. That is what makes it safe to read from
// public infrastructure at all — a lying node is skipped, not trusted.
func archivecmd(args []string) {
	if len(args) == 0 {
		archiveUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "put":
		archivePut(args[1:])
	case "get":
		archiveGet(args[1:])
	case "check":
		archiveCheck(args[1:])
	case "health":
		archiveHealth(args[1:])
	case "-h", "--help":
		archiveUsage()
	default:
		fmt.Fprintf(os.Stderr, "archive: unknown subcommand %q (want put|get|check|health)\n", args[0])
		os.Exit(2)
	}
}

func archiveUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore archive put -file BODY [-dir D] [-ipfs http://127.0.0.1:5001] [-ttl 0]
        (mirror one body to every configured substrate; prints the CID and
         which substrates accepted it)
  spore archive get -cid HEX -out FILE [-dir D] [-ipfs URL]
        (fetch from the first substrate that serves CID-verified bytes)
  spore archive check -cid HEX [-dir D] [-ipfs URL]
        (per-substrate availability: how many independent copies exist)
  spore archive health [-dir D] [-ipfs URL]
        (which substrates are reachable right now)

Substrates are additive: pass -dir for a local mirror, -ipfs for a Kubo
daemon. Publishing needs at least one; DURABILITY needs at least two, and
`+"`put`"+` says so plainly when only one accepted.

-ttl 0 means "keep indefinitely" — correct for an archive. Message bodies
that must compost belong on a TTL store, not here: IPFS deletion is
best-effort and any node that fetched a body may keep it forever.`)
}

// buildArchive assembles a MultiStore from the substrate flags.
func buildArchive(dir, ipfsAPI, indexDir string) (*store.MultiStore, error) {
	var subs []store.Substrate

	if dir != "" {
		ds, err := store.NewDiskStore(dir)
		if err != nil {
			return nil, fmt.Errorf("archive: disk substrate: %w", err)
		}
		subs = append(subs, store.Substrate{Name: "disk", Store: ds})
	}
	if ipfsAPI != "" {
		idx := indexDir
		if idx == "" {
			idx = "."
		}
		is, err := store.NewIPFSStore(store.IPFSConfig{
			APIURL:    ipfsAPI,
			IndexPath: strings.TrimRight(idx, "/\\") + "/ipfs-index.json",
			Timeout:   60 * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("archive: ipfs substrate: %w", err)
		}
		subs = append(subs, store.Substrate{Name: "ipfs", Store: is})
	}
	if len(subs) == 0 {
		return nil, errors.New("archive: no substrates configured — pass -dir and/or -ipfs")
	}
	return store.NewMultiStore(subs...)
}

func archiveFlags(fs *flag.FlagSet) (dir, ipfsAPI, index *string) {
	dir = fs.String("dir", "", "local disk mirror directory")
	ipfsAPI = fs.String("ipfs", "", "Kubo HTTP API URL (e.g. http://127.0.0.1:5001)")
	index = fs.String("index-dir", "", "where to keep the ipfs cid->path index (default: current dir)")
	return
}

func archivePut(args []string) {
	fs := flag.NewFlagSet("archive put", flag.ExitOnError)
	file := fs.String("file", "", "the body file to mirror")
	ttl := fs.Duration("ttl", 0, "retention; 0 = keep indefinitely (archive default)")
	dir, ipfsAPI, index := archiveFlags(fs)
	_ = fs.Parse(args)

	if *file == "" {
		check(errors.New("archive put: -file is required"))
	}
	body, err := os.ReadFile(*file)
	check(err)

	ms, err := buildArchive(*dir, *ipfsAPI, *index)
	check(err)

	cid := ratchetwire.BodyCID(body)
	// An archive keeps things. A zero TTL must mean "no expiry", not "expired
	// a nanosecond ago", so it is mapped to a far-future deadline explicitly.
	deadline := time.Now().Add(100 * 365 * 24 * time.Hour)
	if *ttl > 0 {
		deadline = time.Now().Add(*ttl)
	}

	rep, err := ms.PutWithReport(cid, body, deadline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAILED: %v\n", err)
		for name, e := range rep.Failed {
			fmt.Fprintf(os.Stderr, "  %-6s %v\n", name, e)
		}
		os.Exit(1)
	}

	fmt.Printf("cid         %s\n", hex.EncodeToString(cid[:]))
	fmt.Printf("size        %d bytes\n", len(body))
	fmt.Printf("substrates  %s\n", strings.Join(ms.Names(), ", "))
	fmt.Printf("mirrored    %s\n", rep)
	for name, e := range rep.Failed {
		fmt.Printf("  FAILED %-6s %v\n", name, e)
	}
	if !rep.Durable() {
		fmt.Println()
		fmt.Println("WARNING: only ONE substrate holds this body. That is publication,")
		fmt.Println("not durability — add another substrate before relying on it.")
	}
	fmt.Println()
	fmt.Printf("Recover with: spore archive get -cid %s -out FILE ...\n", hex.EncodeToString(cid[:]))
}

func parseCIDFlag(s string) [32]byte {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != 32 {
		check(errors.New("archive: -cid must be 64 hex characters (a 32-byte sha256)"))
	}
	var cid [32]byte
	copy(cid[:], raw)
	return cid
}

func archiveGet(args []string) {
	fs := flag.NewFlagSet("archive get", flag.ExitOnError)
	cidHex := fs.String("cid", "", "the body CID (64 hex)")
	out := fs.String("out", "", "write the body here (default: stdout)")
	dir, ipfsAPI, index := archiveFlags(fs)
	_ = fs.Parse(args)

	if *cidHex == "" {
		check(errors.New("archive get: -cid is required"))
	}
	cid := parseCIDFlag(*cidHex)
	ms, err := buildArchive(*dir, *ipfsAPI, *index)
	check(err)

	body, err := ms.Get(cid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "UNRECOVERABLE: %v\n", err)
		os.Exit(1)
	}
	if *out == "" {
		os.Stdout.Write(body)
		return
	}
	check(os.WriteFile(*out, body, 0600))
	fmt.Fprintf(os.Stderr, "recovered %d bytes (cid verified) -> %s\n", len(body), *out)
}

func archiveCheck(args []string) {
	fs := flag.NewFlagSet("archive check", flag.ExitOnError)
	cidHex := fs.String("cid", "", "the body CID (64 hex)")
	dir, ipfsAPI, index := archiveFlags(fs)
	_ = fs.Parse(args)

	if *cidHex == "" {
		check(errors.New("archive check: -cid is required"))
	}
	cid := parseCIDFlag(*cidHex)
	ms, err := buildArchive(*dir, *ipfsAPI, *index)
	check(err)

	avail := ms.Availability(cid)
	names := make([]string, 0, len(avail))
	for n := range avail {
		names = append(names, n)
	}
	sort.Strings(names)

	copies := 0
	fmt.Printf("cid %s\n\n", *cidHex)
	for _, n := range names {
		mark := "MISSING"
		if avail[n] {
			mark = "OK"
			copies++
		}
		fmt.Printf("  %-8s %s\n", n, mark)
	}
	fmt.Printf("\nverified copies: %d\n", copies)
	switch {
	case copies == 0:
		fmt.Println("UNRECOVERABLE: no substrate holds a valid copy.")
		os.Exit(1)
	case copies == 1:
		fmt.Println("AT RISK: a single copy is not durable. Mirror it again.")
	default:
		fmt.Println("DURABLE: recoverable from more than one independent substrate.")
	}
}

func archiveHealth(args []string) {
	fs := flag.NewFlagSet("archive health", flag.ExitOnError)
	dir, ipfsAPI, index := archiveFlags(fs)
	_ = fs.Parse(args)

	if *ipfsAPI != "" {
		idx := *index
		if idx == "" {
			idx = "."
		}
		is, err := store.NewIPFSStore(store.IPFSConfig{
			APIURL:    *ipfsAPI,
			IndexPath: strings.TrimRight(idx, "/\\") + "/ipfs-index.json",
			Timeout:   15 * time.Second,
		})
		if err != nil {
			fmt.Printf("  ipfs     CONFIG ERROR %v\n", err)
		} else if err := is.Health(); err != nil {
			fmt.Printf("  ipfs     UNREACHABLE  %v\n", err)
		} else {
			fmt.Printf("  ipfs     OK           %d body(ies) indexed\n", is.Len())
		}
	}
	if *dir != "" {
		ds, err := store.NewDiskStore(*dir)
		if err != nil {
			fmt.Printf("  disk     ERROR        %v\n", err)
		} else {
			fmt.Printf("  disk     OK           %d body(ies)\n", ds.Len())
		}
	}
	if *dir == "" && *ipfsAPI == "" {
		fmt.Println("no substrates configured (pass -dir and/or -ipfs)")
	}
}
