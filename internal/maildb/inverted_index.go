// Package tokens implements a token-level inverted index for MailDB messages,
// giving O(k + n·p) query performance instead of O(n) substring scanning,
// where k = total unique terms in the index and p = phrase window size.
package maildb

import (
	"regexp"
	"strings"
	"sync"
)

var tokenRegex = regexp.MustCompile(`[^\s]+`)

// tokenize splits text into lowercase tokens (non-whitespace runs).
func tokenize(text string) []string {
	matches := tokenRegex.FindAllString(strings.ToLower(text), -1)
	if len(matches) == 0 {
		return nil
	}
	return matches
}

// InvertedIndex is a thread-safe inverted index for message search.
// Each token maps to the set of message indices that contain it.
type InvertedIndex struct {
	mu     sync.RWMutex
	tokens map[string]map[int]struct{} // term -> message index set
	msgAt  []int64                     // parallel array: message timestamp at[index]
	snip   []string                    // parallel array: snippet at[index]
	peer   []string                    // parallel array: peer at[index]
	seg    map[int]string              // segment prefix mapping for range queries
	n      int                         // count of indexed messages
}

// NewInvertedIndex creates an empty inverted index with pre-allocated capacity.
func NewInvertedIndex(capacity int) *InvertedIndex {
	if capacity <= 0 {
		capacity = 1024
	}
	return &InvertedIndex{
		tokens: make(map[string]map[int]struct{}, capacity/10),
		msgAt:  make([]int64, 0, capacity),
		snip:   make([]string, 0, capacity),
		peer:   make([]string, 0, capacity),
		seg:    make(map[int]string, 0),
		n:      0,
	}
}

// Add records one message into the index. The message must not exceed maxLen bytes
// before tokenization; longer messages are truncated silently so a single huge
// body cannot turn the index into an allocation sink.
const maxSnippetLen = 512 // cap per-message snippet before tokenization

func (idx *InvertedIndex) Add(txid, peerAddr string, atUnix int64, snippet string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	// Truncate snippet to prevent unbounded token accumulation from a single message.
	if len(snippet) > maxSnippetLen {
		snippet = snippet[:maxSnippetLen]
	}

	toks := tokenize(snippet)
	msgIdx := len(idx.msgAt)
	idx.msgAt = append(idx.msgAt, atUnix)
	idx.snip = append(idx.snip, snippet)
	idx.peer = append(idx.peer, strings.ToLower(peerAddr))

	for _, tok := range toks {
		s := idx.tokens[tok]
		if s == nil {
			s = make(map[int]struct{})
			idx.tokens[tok] = s
		}
		s[msgIdx] = struct{}{}
	}

	idx.n++
}

// SearchAnd returns message indices whose snippets contain ALL of the given terms.
// SearchAnd returns message indices whose snippets contain ALL of the given
// terms as whole tokens.
func (idx *InvertedIndex) SearchAnd(terms []string) []int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if len(terms) == 0 {
		return nil
	}

	// Find smallest term first (optimisation: start with most-restrictive set).
	smallest := ""
	smallCount := ^int(0)
	for _, t := range terms {
		set := idx.tokens[t]
		if set == nil {
			return nil // early-out: missing term => no hits
		}
		if len(set) < smallCount {
			smallCount = len(set)
			smallest = t
		}
	}

	base := idx.tokens[smallest]
	result := make([]int, 0, smallCount)
	for mIdx := range base {
		match := true
		for _, tok := range terms {
			if tok == smallest {
				continue
			}
			if _, ok := idx.tokens[tok][mIdx]; !ok {
				match = false
				break
			}
		}
		if match {
			result = append(result, mIdx)
		}
	}
	return result
}

// SearchOr returns message indices containing ANY of the given terms.
func (idx *InvertedIndex) SearchOr(terms []string) []int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if len(terms) == 0 {
		return nil
	}

	hits := make(map[int]struct{})
	for _, tok := range terms {
		if set := idx.tokens[tok]; set != nil {
			for mIdx := range set {
				hits[mIdx] = struct{}{}
			}
		}
	}

	result := make([]int, 0, len(hits))
	for mIdx := range hits {
		result = append(result, mIdx)
	}
	return result
}

// SearchNot filters out messages containing any of the excluded terms.
func (idx *InvertedIndex) SearchNot(results []int, exclude []string) []int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if len(exclude) == 0 || len(results) == 0 {
		return results
	}

	exclMap := make(map[string]bool)
	for _, e := range exclude {
		exclMap[e] = true
	}

	filtered := make([]int, 0, len(results))
	for _, mIdx := range results {
		snippet := strings.ToLower(idx.snip[mIdx])
		hasExcluded := false
		for ex := range exclMap {
			if strings.Contains(snippet, ex) {
				hasExcluded = true
				break
			}
		}
		if !hasExcluded {
			filtered = append(filtered, mIdx)
		}
	}
	return filtered
}

// PhraseSearch finds contiguous multi-term sequences within a configurable window.
// Window defines how far apart two consecutive terms can be before the match is broken.
func (idx *InvertedIndex) PhraseSearch(phrase string, window int) []int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if window <= 0 || window > 10 {
		window = 3 // default window
	}

	words := tokenize(phrase)
	if len(words) == 0 {
		return nil
	}
	if len(words) == 1 {
		return idx.SearchOr(words)
	}

	// Build candidate positions using the first term as anchor, then verify subsequent terms fall within window.
	first := idx.tokens[words[0]]
	if first == nil {
		return nil
	}

	var hits []int
	seen := make(map[int]bool)

	for pos := range first {
		snip := idx.snip[pos]
		lower := strings.ToLower(snip)

		start := 0
		prevEnd := -1
		found := 1

		for i := 1; i < len(words); i++ {
			nextStart := strings.Index(lower[start:], words[i])
			if nextStart == -1 {
				break
			}
			actualPos := start + nextStart
			endOfWord := actualPos + len(words[i])

			// Check if this term falls within window of previous match
			if prevEnd >= 0 && actualPos-prevEnd > window*10 {
				break // too far
			}

			found++
			prevEnd = endOfWord
			start = nextStart + 1
		}

		if found == len(words) {
			if !seen[pos] {
				hits = append(hits, pos)
				seen[pos] = true
			}
		}
	}

	return hits
}

// PositionsContaining returns the union of index positions whose token
// CONTAINS any of the given terms as a substring. This is the search
// prefilter primitive for substring semantics: a term occurring anywhere in
// a snippet always occurs inside one whitespace-delimited token (tokens are
// maximal non-whitespace runs), so any message whose text contains a term
// has a token containing it. The result is therefore a SUPERSET of the
// exact matches; the caller applies its exact matcher to filter. One call
// scans the vocabulary once (O(vocab) string contains) instead of the
// caller scanning every snippet per term (O(n·terms)).
func (idx *InvertedIndex) PositionsContaining(terms []string) map[int]struct{} {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	out := make(map[int]struct{})
	if len(terms) == 0 {
		return out
	}
	for tok, set := range idx.tokens {
		for _, t := range terms {
			if strings.Contains(tok, t) {
				for pos := range set {
					out[pos] = struct{}{}
				}
				break
			}
		}
	}
	return out
}

// SegmentByDate builds segment keys ("year.month") to enable prefix-range queries.
func (idx *InvertedIndex) SegmentByDate(week int) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.seg = make(map[int]string, len(idx.msgAt))
	for i, ts := range idx.msgAt {
		sec := uint64(ts) / uint64(week*7*86400)
		idx.seg[i] = string(rune(sec % 256))
	}
}
