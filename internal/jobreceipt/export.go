package jobreceipt

// The accounting export (docs/JOB_RECEIPT_V1.md §9).
//
// The column order and the sort are protocol, not presentation: two exports of
// the same directory must be byte-identical, or an accountant cannot diff last
// month against this one and a reconciliation becomes a spot-the-difference.
// Amounts stay integer strings; the reporting currency is chosen by whoever
// reads the file, at a rate they can defend.

import "sort"

// ExportColumns is the §9 header, in order.
var ExportColumns = []string{
	"period_start",
	"period_end",
	"category",
	"summary",
	"rail",
	"network",
	"asset",
	"amount_atomic",
	"txid",
	"settlement_time",
	"evidence",
	"receipt_id",
}

// ExportRow is one settlement line of one spend receipt.
type ExportRow struct {
	PeriodStart    string
	PeriodEnd      string
	Category       string
	Summary        string
	Rail           string
	Network        string
	Asset          string
	AmountAtomic   string
	TxID           string
	SettlementTime string
	// Evidence is per ROW, copied from the record: a single txid-less line makes
	// the whole declaration self-declared, and every row of it must say so.
	Evidence  string
	ReceiptID string
}

// Fields returns the row in ExportColumns order.
func (r ExportRow) Fields() []string {
	return []string{
		r.PeriodStart, r.PeriodEnd, r.Category, r.Summary,
		r.Rail, r.Network, r.Asset, r.AmountAtomic, r.TxID,
		r.SettlementTime, r.Evidence, r.ReceiptID,
	}
}

// RowsFromSpend flattens one record into rows, one per settlement line. The
// period is blank when the record makes no period claim rather than being
// invented from the settlement dates.
func RowsFromSpend(rec *SpendRecord, receiptID string) []ExportRow {
	var from, to string
	if rec.Period != nil {
		from, to = rec.Period.From, rec.Period.To
	}
	rows := make([]ExportRow, 0, len(rec.Settlement))
	for _, s := range rec.Settlement {
		rows = append(rows, ExportRow{
			PeriodStart:    from,
			PeriodEnd:      to,
			Category:       rec.Service.Category,
			Summary:        rec.Service.Summary,
			Rail:           s.Rail,
			Network:        s.Network,
			Asset:          s.Asset,
			AmountAtomic:   s.AmountAtomic,
			TxID:           s.TxID,
			SettlementTime: s.SettledAt,
			Evidence:       rec.Evidence,
			ReceiptID:      receiptID,
		})
	}
	return rows
}

// SortRows applies §9's order — settlement time, then txid — with the remaining
// fields as tie-breakers so one directory always yields one byte sequence.
func SortRows(rows []ExportRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		for _, pair := range [][2]string{
			{a.SettlementTime, b.SettlementTime},
			{a.TxID, b.TxID},
			{a.ReceiptID, b.ReceiptID},
			{a.Rail, b.Rail},
			{a.Network, b.Network},
			{a.Asset, b.Asset},
			{a.AmountAtomic, b.AmountAtomic},
			{a.Category, b.Category},
			{a.Summary, b.Summary},
			{a.PeriodStart, b.PeriodStart},
			{a.PeriodEnd, b.PeriodEnd},
		} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return false
	})
}
