package ratchetwire

import (
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

// BodyStore is the off-chain storage seam for E2 frames. It matches
// store.Store so disk, HTTP, memory, and spore-peer adapters are interchangeable.
type BodyStore = store.Store

// PutBody stores an already serialized E2 frame and returns its opaque pointer.
func PutBody(st BodyStore, body []byte, deadline time.Time) (Pointer, error) {
	// PointerPayload carries Unix seconds, and HTTP stores receive the same
	// precision. Normalize once before validation and storage so the pointer
	// deadline and the body's retention deadline cannot diverge at a second
	// boundary.
	deadline = time.Unix(deadline.Unix(), 0)
	if deadline.IsZero() || !deadline.After(time.Now()) {
		return Pointer{}, ErrBadFrame
	}
	cid := BodyCID(body)
	if err := st.Put(cid, body, deadline); err != nil {
		return Pointer{}, err
	}
	return Pointer{CID: cid, BurnDeadline: uint64(deadline.Unix())}, nil
}

func GetBody(st BodyStore, p Pointer, now time.Time) ([]byte, error) {
	if p.BurnDeadline == 0 || now.Unix() >= int64(p.BurnDeadline) {
		return nil, ErrExpired
	}
	body, err := st.Get(p.CID)
	if err != nil {
		return nil, err
	}
	if BodyCID(body) != p.CID {
		return nil, ErrBadFrame
	}
	return body, nil
}

var _ BodyStore = store.Store(nil)
