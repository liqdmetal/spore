// Package notify delivers privacy-preserving arrival notifications.
// Provider payloads contain only message metadata; plaintext is deliberately
// never serialized or sent by this package.
package notify

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Event is produced after a message has been decrypted locally. It contains
// notification metadata only; plaintext has no representation in this package.
type Event struct {
	TxID     string
	Subject  string
	Received time.Time
}

// Options configures one or more notification providers. Secrets should be
// supplied through NewFromEnv rather than command-line arguments.
type Options struct {
	WebhookURL   string
	WebhookToken string
	EmailTo      string
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPFrom     string
	SMTPPassword string
	SMSTo        string
	TwilioSID    string
	TwilioFrom   string
	TwilioAuth   string
	HTTPClient   *http.Client
}

// Dispatcher sends one metadata-only event to every configured provider.
type Dispatcher struct {
	options         Options
	webhookToken    string
	smtpPassword    string
	twilioAuthToken string
	client          *http.Client
}

// New validates provider configuration and returns a dispatcher. Empty options
// are valid and produce a no-op dispatcher.
func New(o Options) (*Dispatcher, error) {
	for name, value := range map[string]string{
		"SMTPHost": o.SMTPHost, "EmailTo": o.EmailTo, "SMTPFrom": o.SMTPFrom,
		"SMTPUsername": o.SMTPUsername, "SMSTo": o.SMSTo, "TwilioSID": o.TwilioSID,
		"TwilioFrom": o.TwilioFrom, "WebhookToken": o.WebhookToken,
	} {
		if strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("notify: %s must not contain CR/LF", name)
		}
	}
	if o.SMTPHost != "" || o.EmailTo != "" || o.SMTPFrom != "" || o.SMTPUsername != "" || o.SMTPPassword != "" {
		if o.SMTPHost == "" || o.EmailTo == "" || o.SMTPFrom == "" {
			return nil, errors.New("notify: SMTP requires SMTPHost, SMTPFrom, and EmailTo")
		}
		if o.SMTPPort == 0 {
			o.SMTPPort = 587
		}
	}
	if o.SMSTo != "" && (o.TwilioSID == "" || o.TwilioFrom == "") {
		return nil, errors.New("notify: SMS requires TwilioSID and TwilioFrom")
	}
	if o.WebhookURL != "" {
		u, err := url.Parse(o.WebhookURL)
		if err != nil || u.Scheme != "https" && u.Scheme != "http" || u.Host == "" {
			return nil, errors.New("notify: WebhookURL must be an absolute http(s) URL")
		}
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Dispatcher{options: o, webhookToken: o.WebhookToken, smtpPassword: o.SMTPPassword, twilioAuthToken: o.TwilioAuth, client: client}, nil
}

// NewFromEnv loads secrets from environment variables. Non-secret endpoints
// remain in Options so they can come from config files or service flags.
//
// SPORE_NOTIFY_WEBHOOK_TOKEN
// SPORE_NOTIFY_SMTP_PASSWORD
// SPORE_NOTIFY_TWILIO_AUTH_TOKEN
func NewFromEnv(o Options) (*Dispatcher, error) {
	if o.WebhookToken == "" {
		o.WebhookToken = os.Getenv("SPORE_NOTIFY_WEBHOOK_TOKEN")
	}
	if o.SMTPPassword == "" {
		o.SMTPPassword = os.Getenv("SPORE_NOTIFY_SMTP_PASSWORD")
	}
	if o.TwilioAuth == "" {
		o.TwilioAuth = os.Getenv("SPORE_NOTIFY_TWILIO_AUTH_TOKEN")
	}
	return New(o)
}

// Send delivers metadata only. A configured provider failure is returned;
// callers can log it without stopping the message receiver.
func (d *Dispatcher) Send(e Event) error {
	if d == nil {
		return nil
	}
	if strings.ContainsAny(e.TxID, "\r\n") || strings.ContainsAny(e.Subject, "\r\n") {
		return fmt.Errorf("notify: txid and subject must not contain CR/LF")
	}
	var errs []string
	if d.options.WebhookURL != "" {
		if err := d.sendWebhook(e); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if d.options.EmailTo != "" {
		if err := d.sendEmail(e); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if d.options.SMSTo != "" {
		if err := d.sendSMS(e); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (d *Dispatcher) sendWebhook(e Event) error {
	payload := struct {
		Event    string `json:"event"`
		TxID     string `json:"txid"`
		Subject  string `json:"subject"`
		Received string `json:"received_at"`
	}{"message.available", e.TxID, safeSubject(e.Subject), e.Received.UTC().Format(time.RFC3339)}
	if e.Received.IsZero() {
		payload.Received = ""
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify webhook: marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, d.options.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("notify webhook: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if d.webhookToken != "" {
		req.Header.Set("Authorization", "Bearer "+d.webhookToken)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify webhook: status %s", resp.Status)
	}
	return nil
}

func (d *Dispatcher) sendEmail(e Event) error {
	addr := d.options.SMTPHost + ":" + strconv.Itoa(d.options.SMTPPort)
	headers := []string{
		"From: " + d.options.SMTPFrom,
		"To: " + d.options.EmailTo,
		"Subject: " + safeSubject(e.Subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}
	body := "You have a new private Spore message. Open your Spore client to read it.\r\n"
	msg := []byte(strings.Join(headers, "\r\n") + "\r\n\r\n" + body)
	var auth smtp.Auth
	if d.options.SMTPUsername != "" {
		auth = smtp.PlainAuth("", d.options.SMTPUsername, d.smtpPassword, d.options.SMTPHost)
	}
	var conn net.Conn
	var err error
	if d.options.SMTPPort == 465 {
		conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: d.options.SMTPHost, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
	}
	if err != nil {
		return fmt.Errorf("notify email: dial: %w", err)
	}
	c, err := smtp.NewClient(conn, d.options.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("notify email: SMTP client: %w", err)
	}
	defer c.Close()
	if d.options.SMTPPort != 465 {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("notify email: SMTP server does not advertise STARTTLS")
		}
		if err := c.StartTLS(&tls.Config{ServerName: d.options.SMTPHost, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("notify email: STARTTLS: %w", err)
		}
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("notify email: auth: %w", err)
		}
	}
	if err := c.Mail(d.options.SMTPFrom); err != nil {
		return err
	}
	if err := c.Rcpt(d.options.EmailTo); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err = w.Write(msg); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (d *Dispatcher) sendSMS(e Event) error {
	endpoint := "https://api.twilio.com/2010-04-01/Accounts/" + url.PathEscape(d.options.TwilioSID) + "/Messages.json"
	form := url.Values{"To": {d.options.SMSTo}, "From": {d.options.TwilioFrom}, "Body": {"Spore: you have a new private message. Open your Spore client."}}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("notify SMS: request: %w", err)
	}
	req.SetBasicAuth(d.options.TwilioSID, d.twilioAuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify SMS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify SMS: status %s", resp.Status)
	}
	return nil
}

func safeSubject(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "Spore private message"
	}
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
