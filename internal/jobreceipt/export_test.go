package jobreceipt

import (
	"strings"
	"testing"
)

func TestExportRowMatchesColumnOrder(t *testing.T) {
	rec := spendRecord()
	rec.Period = &Period{From: "2026-10-01T00:00:00Z", To: "2026-10-31T23:59:59Z"}
	rows := RowsFromSpend(rec, "abc123")
	if len(rows) != 1 {
		t.Fatalf("one settlement line produced %d rows", len(rows))
	}
	fields := rows[0].Fields()
	if len(fields) != len(ExportColumns) {
		t.Fatalf("row has %d fields for %d columns", len(fields), len(ExportColumns))
	}
	byName := map[string]string{}
	for i, name := range ExportColumns {
		byName[name] = fields[i]
	}
	for name, want := range map[string]string{
		"period_start":    "2026-10-01T00:00:00Z",
		"period_end":      "2026-10-31T23:59:59Z",
		"category":        "plumbing.emergency",
		"rail":            "dero",
		"amount_atomic":   "2500000000000",
		"txid":            strings.Repeat("ef", 32),
		"settlement_time": "2026-10-24T16:04:00Z",
		"evidence":        EvidenceChain,
		"receipt_id":      "abc123",
	} {
		if byName[name] != want {
			t.Errorf("%s = %q, want %q", name, byName[name], want)
		}
	}
}

// A record that makes no period claim exports blank period columns: inventing a
// span from the settlement dates would put a date in an accountant's file that
// nobody signed.
func TestExportPeriodIsBlankWhenAbsent(t *testing.T) {
	rec := spendRecord()
	rec.Period = nil
	rows := RowsFromSpend(rec, "id")
	if rows[0].PeriodStart != "" || rows[0].PeriodEnd != "" {
		t.Fatalf("absent period exported as %q..%q", rows[0].PeriodStart, rows[0].PeriodEnd)
	}
}

func TestExportEvidenceTravelsPerRow(t *testing.T) {
	rec := spendRecord()
	rec.Settlement = append(rec.Settlement, Settlement{
		Rail: "cash", Network: "none", Asset: "usd",
		AmountAtomic: "12000", SettledAt: "2026-10-24T18:00:00Z",
	})
	rec.Evidence = DeriveEvidence(rec.Settlement)
	if rec.Evidence != EvidenceSelf {
		t.Fatalf("one txid-less line should make the record %q, got %q", EvidenceSelf, rec.Evidence)
	}
	rows := RowsFromSpend(rec, "id")
	for _, row := range rows {
		if row.Evidence != EvidenceSelf {
			t.Fatalf("row exported as %q while the record is %q", row.Evidence, rec.Evidence)
		}
	}
	if rows[1].TxID != "" {
		t.Fatalf("a self-declared row must leave txid empty, got %q", rows[1].TxID)
	}
}

func TestSortRowsIsTotalAndTimeFirst(t *testing.T) {
	rows := []ExportRow{
		{SettlementTime: "2026-10-24T16:00:00Z", TxID: strings.Repeat("bb", 32), ReceiptID: "r3"},
		{SettlementTime: "2026-10-02T09:00:00Z", TxID: strings.Repeat("dd", 32), ReceiptID: "r1"},
		{SettlementTime: "2026-10-24T16:00:00Z", TxID: strings.Repeat("aa", 32), ReceiptID: "r2"},
		{SettlementTime: "2026-10-24T16:00:00Z", TxID: strings.Repeat("aa", 32), ReceiptID: "r0"},
	}
	SortRows(rows)
	want := []string{"r1", "r0", "r2", "r3"}
	for i, id := range want {
		if rows[i].ReceiptID != id {
			t.Fatalf("row %d = %s, want %s (order: %+v)", i, rows[i].ReceiptID, id, rows)
		}
	}

	// The sort must be byte-stable: exporting the same directory twice cannot
	// differ because map iteration or file order changed.
	again := []ExportRow{rows[3], rows[1], rows[0], rows[2]}
	SortRows(again)
	for i := range rows {
		if rows[i] != again[i] {
			t.Fatalf("sort is not a function of the rows alone at %d: %+v vs %+v", i, rows[i], again[i])
		}
	}
}
