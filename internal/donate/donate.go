// Package donate holds the per-chain donation rail for the mycelium network.
//
// A mycelium node/relay operator can advertise one address per supported
// chain (DERO / XMR / EVM) as the donation rail. Because identity = your
// wallet address on whatever chain you're on, donation is just a config
// mapping {chain -> address}. The CLI prints the right one for the user's
// current chain (mycelium donate <chain>), and a relay operator publishes all
// of them (mycelium donate --all).
package donate

import (
	"fmt"
	"sort"
	"strings"
)

// Entry is one chain's donation address.
type Entry struct {
	Chain   string
	Address string
	Note    string
}

// Registry maps chain -> address. Populated by the operator. The zero-value
// Registry is valid (empty); use Register to add chains at startup.
type Registry struct {
	m map[string]Entry
}

// New returns an empty registry.
func New() *Registry { return &Registry{m: map[string]Entry{}} }

// Register adds (or replaces) a chain's donation address.
func (r *Registry) Register(e Entry) {
	if r.m == nil {
		r.m = map[string]Entry{}
	}
	r.m[e.Chain] = e
}

// Get returns the donation entry for chain (case-insensitive) or false.
func (r *Registry) Get(chain string) (Entry, bool) {
	if r.m == nil {
		return Entry{}, false
	}
	e, ok := r.m[strings.ToLower(strings.TrimSpace(chain))]
	return e, ok
}

// Chains returns the registered chain names, sorted.
func (r *Registry) Chains() []string {
	out := make([]string, 0, len(r.m))
	for c := range r.m {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Render prints all donation addresses as a short table.
func (r *Registry) Render() string {
	var b strings.Builder
	b.WriteString("mycelium donation rail — one address per chain:\n\n")
	for _, c := range r.Chains() {
		e := r.m[c]
		fmt.Fprintf(&b, "  %-6s %s\n", e.Chain, e.Address)
		if e.Note != "" {
			fmt.Fprintf(&b, "         └ %s\n", e.Note)
		}
	}
	return b.String()
}
