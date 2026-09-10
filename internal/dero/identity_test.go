package dero

import "testing"

func TestEntryIdentitySeparatesSameTransactionPayloads(t *testing.T) {
	a := Entry{TXID: "same", Height: 10, TopoHeight: 11, Amount: 1, Sender: "s", TransactionPos: 2, Pos: 1}
	b := a
	if EntryIdentity(a, []byte("a")) == EntryIdentity(b, []byte("b")) {
		t.Fatal("distinct payloads collapsed into one identity")
	}
	if EntryIdentity(Entry{}, nil) != "" {
		t.Fatal("empty transaction received an identity")
	}
}

func TestEntryIdentitySeparatesTransferPositions(t *testing.T) {
	a := Entry{TXID: "same", Height: 10, TopoHeight: 11, Amount: 1, Sender: "s", TransactionPos: 2, Pos: 1}
	b := a
	b.Pos = 2
	if EntryIdentity(a, []byte("same")) == EntryIdentity(b, []byte("same")) {
		t.Fatal("distinct transfer positions collapsed into one identity")
	}
}

func TestEntryIdentityStableAcrossSameEntry(t *testing.T) {
	e := Entry{TXID: "tx", Height: 42, TopoHeight: 43, Amount: 1, Sender: "s", TransactionPos: 4, Pos: 5}
	one := EntryIdentity(e, []byte("payload"))
	two := EntryIdentity(e, []byte("payload"))
	if one == "" || one != two {
		t.Fatal("entry identity is not stable")
	}
}
