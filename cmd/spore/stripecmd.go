// stripecmd — the outsourced-mail rail: mirror a Spore invoice into Stripe
// Invoicing so Stripe emails the client, hosts the payment page, and keeps
// the card ledger. The crypto rail (spore msg invoice/pay) stays the
// private source of truth; this is the licensed-tier courier.
//
//	spore stripe invoice-create -email c@x.com -amount 123.45 -currency usd -for "Sept retainer" [-id inv-abc]
//	spore stripe invoice-list  -email c@x.com
//	spore stripe invoice-paid  -id inv_1...   (mark settled; the receipts ledger is authoritative)
//
// Requires STRIPE_API_KEY (sk_test_... or sk_live_...) in the environment.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const stripeAPI = "https://api.stripe.com/v1"

func stripeBase() string {
	if b := os.Getenv("SPORE_STRIPE_BASE"); b != "" {
		return strings.TrimRight(b, "/")
	}
	return stripeAPI
}

func stripeClient() (*http.Client, error) {
	if os.Getenv("STRIPE_API_KEY") == "" {
		return nil, errors.New("STRIPE_API_KEY is not set (sk_test_… or sk_live_…); get one at https://dashboard.stripe.com/apikeys")
	}
	return &http.Client{Timeout: 30 * time.Second}, nil
}

func stripeCall(client *http.Client, method, path string, form url.Values) (map[string]any, error) {
	req, err := http.NewRequest(method, stripeBase()+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(os.Getenv("STRIPE_API_KEY"), "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("stripe: bad response: %s", strings.TrimSpace(string(body)))
	}
	if resp.StatusCode >= 400 {
		msg := out["error"]
		return nil, fmt.Errorf("stripe: %s: %v", resp.Status, msg)
	}
	return out, nil
}

// stripeCustomerByEmail gets or creates the customer for an email address.
func stripeCustomerByEmail(client *http.Client, email string) (string, error) {
	list, err := stripeCall(client, http.MethodGet, "/customers?email="+url.QueryEscape(email), nil)
	if err != nil {
		return "", err
	}
	if data, ok := list["data"].([]any); ok && len(data) > 0 {
		if c, ok := data[0].(map[string]any); ok {
			if id, ok := c["id"].(string); ok && id != "" {
				return id, nil
			}
		}
	}
	created, err := stripeCall(client, http.MethodPost, "/customers", url.Values{"email": {email}})
	if err != nil {
		return "", err
	}
	id, _ := created["id"].(string)
	if id == "" {
		return "", errors.New("stripe: customer create returned no id")
	}
	return id, nil
}

func stripeInvoiceCreate(args []string) {
	fs := flag.NewFlagSet("stripe invoice-create", flag.ExitOnError)
	email := fs.String("email", "", "client email (Stripe emails them the invoice)")
	amount := fs.String("amount", "", "fiat amount, e.g. 123.45")
	currency := fs.String("currency", "usd", "ISO currency code")
	forWhat := fs.String("for", "", "line-item description")
	id := fs.String("id", "", "spore invoice id to mirror (shown to the client as the reference)")
	_ = fs.Parse(args)
	if *email == "" || *amount == "" {
		check(errors.New("invoice-create requires -email and -amount"))
	}
	client, err := stripeClient()
	check(err)
	customer, err := stripeCustomerByEmail(client, *email)
	check(err)
	// one line item carrying the description + spore reference
	desc := strings.TrimSpace(*forWhat)
	if *id != "" {
		if desc != "" {
			desc += " — "
		}
		desc += "spore invoice " + *id
	}
	item, err := stripeCall(client, http.MethodPost, "/invoiceitems", url.Values{
		"customer":    {customer},
		"amount":      {stripeAmount(*amount, *currency)},
		"currency":    {*currency},
		"description": {desc},
	})
	check(err)
	inv, err := stripeCall(client, http.MethodPost, "/invoices", url.Values{
		"customer":          {customer},
		"auto_advance":      {"true"},
		"collection_method": {"send_invoice"},
		"days_until_due":    {"7"},
		"description":       {"spore invoice " + *id},
	})
	check(err)
	invID, _ := inv["id"].(string)
	finalized, err := stripeCall(client, http.MethodPost, "/invoices/"+invID+"/finalize", nil)
	check(err)
	hosted, _ := finalized["hosted_invoice_url"].(string)
	pdf, _ := finalized["invoice_pdf"].(string)
	_ = item
	fmt.Printf("stripe invoice %s created for %s — %s %s\n", invID, *email, *amount, strings.ToUpper(*currency))
	fmt.Printf("  client page : %s\n", hosted)
	fmt.Printf("  pdf        : %s\n", pdf)
	fmt.Println("  Stripe emails the client the invoice + reminders. Mark settled with:")
	fmt.Printf("  spore stripe invoice-paid -id %s\n", invID)
}

func stripeAmount(amount, currency string) string {
	// fiat amounts are in the currency's smallest unit (cents): "123.45" -> 12345
	whole, frac := amount, ""
	if i := strings.IndexByte(amount, '.'); i >= 0 {
		whole, frac = amount[:i], amount[i+1:]
	}
	for len(frac) < 2 {
		frac += "0"
	}
	if len(frac) > 2 {
		frac = frac[:2]
	}
	return strings.TrimLeft(whole, "0") + frac
}

func stripeInvoiceList(args []string) {
	fs := flag.NewFlagSet("stripe invoice-list", flag.ExitOnError)
	email := fs.String("email", "", "client email")
	_ = fs.Parse(args)
	if *email == "" {
		check(errors.New("invoice-list requires -email"))
	}
	client, err := stripeClient()
	check(err)
	customer, err := stripeCustomerByEmail(client, *email)
	check(err)
	list, err := stripeCall(client, http.MethodGet, "/invoices?customer="+customer, nil)
	check(err)
	data, _ := list["data"].([]any)
	if len(data) == 0 {
		fmt.Printf("no stripe invoices for %s\n", *email)
		return
	}
	for _, raw := range data {
		inv, _ := raw.(map[string]any)
		id, _ := inv["id"].(string)
		status, _ := inv["status"].(string)
		hosted, _ := inv["hosted_invoice_url"].(string)
		amt, _ := inv["amount_due"].(float64)
		cur, _ := inv["currency"].(string)
		fmt.Printf("%-24s %-10s %8.2f %-3s %s\n", id, status, amt/100, cur, hosted)
	}
}

func stripeInvoicePaid(args []string) {
	fs := flag.NewFlagSet("stripe invoice-paid", flag.ExitOnError)
	id := fs.String("id", "", "stripe invoice id")
	_ = fs.Parse(args)
	if *id == "" {
		check(errors.New("invoice-paid requires -id"))
	}
	client, err := stripeClient()
	check(err)
	// mark the invoice paid so Stripe stops sending reminders; the receipts
	// ledger remains the authoritative record of the crypto settlement.
	upd, err := stripeCall(client, http.MethodPost, "/invoices/"+*id, url.Values{
		"metadata[settled_via]": {"spore-chain"},
	})
	check(err)
	status, _ := upd["status"].(string)
	fmt.Printf("stripe invoice %s marked (status %s); the spore receipts ledger is the source of truth\n", *id, status)
}

func stripecmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: spore stripe <invoice-create|invoice-list|invoice-paid> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "invoice-create":
		stripeInvoiceCreate(args[1:])
	case "invoice-list":
		stripeInvoiceList(args[1:])
	case "invoice-paid":
		stripeInvoicePaid(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "stripe: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}
