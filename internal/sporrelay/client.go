package sporrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the HTTP boundary to RelayOS. It owns only transport configuration;
// RelayOS owns authorization, objective state, and any subsequent execution.
const maxRelayJSONBytes = 1 << 20

type Client struct {
	cfg  *Config
	http *http.Client
}

func NewClient(cfg *Config) *Client {
	if cfg == nil {
		cfg = &Config{}
	}
	return &Client{
		cfg: &Config{RelayerURL: cfg.RelayerURL, APIToken: cfg.APIToken},
		http: &http.Client{
			Timeout: 15 * time.Second,
			// Signed authority envelopes must not be replayed to a redirect target.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// RegisterWorkOrder forwards the caller's already-signed, least-authority
// RelayOS command to POST /v1/commands. It returns the objective record RelayOS
// created; this is registration only, not execution, verification, or payment.
func (c *Client) RegisterWorkOrder(ctx context.Context, command AuthorizedWorkOrderCommand) (ObjectiveRegistrationResult, error) {
	if err := command.Validate(); err != nil {
		return ObjectiveRegistrationResult{}, err
	}
	endpoint, err := c.commandsEndpoint()
	if err != nil {
		return ObjectiveRegistrationResult{}, err
	}
	body, err := json.Marshal(command)
	if err != nil {
		return ObjectiveRegistrationResult{}, fmt.Errorf("sporrelay: encode authorized work order: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ObjectiveRegistrationResult{}, fmt.Errorf("sporrelay: create RelayOS command: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return ObjectiveRegistrationResult{}, fmt.Errorf("sporrelay: submit work order: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return ObjectiveRegistrationResult{}, fmt.Errorf("sporrelay: RelayOS command returned %s: %s", resp.Status, strings.TrimSpace(string(message)))
	}

	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := decodeSingleJSON(resp.Body, &envelope); err != nil {
		return ObjectiveRegistrationResult{}, fmt.Errorf("sporrelay: decode RelayOS command response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error == "" {
			envelope.Error = "RelayOS did not authorize or apply the command"
		}
		return ObjectiveRegistrationResult{}, fmt.Errorf("sporrelay: RelayOS rejected work-order registration: %s", envelope.Error)
	}
	if len(envelope.Result) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Result), []byte("null")) {
		return ObjectiveRegistrationResult{}, fmt.Errorf("sporrelay: RelayOS accepted command without an objective registration result")
	}

	var result ObjectiveRegistrationResult
	if err := decodeSingleJSON(bytes.NewReader(envelope.Result), &result); err != nil {
		return ObjectiveRegistrationResult{}, fmt.Errorf("sporrelay: decode objective registration result: %w", err)
	}
	if !result.matches(command.Command.Payload) {
		return ObjectiveRegistrationResult{}, fmt.Errorf("sporrelay: RelayOS objective registration result does not match submitted work order")
	}
	return result, nil
}

func (c *Client) commandsEndpoint() (string, error) {
	if c == nil || c.cfg == nil || strings.TrimSpace(c.cfg.RelayerURL) == "" {
		return "", ErrNoRelayer
	}
	base, err := url.Parse(strings.TrimSpace(c.cfg.RelayerURL))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return "", fmt.Errorf("sporrelay: RelayOS URL must be an absolute http(s) base URL")
	}
	if base.Scheme != "https" && !isLoopbackHost(base.Hostname()) {
		return "", fmt.Errorf("sporrelay: remote RelayOS registration requires HTTPS; plain HTTP is allowed only on loopback")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/v1/commands"
	return base.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func decodeSingleJSON(reader io.Reader, out any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxRelayJSONBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxRelayJSONBytes {
		return fmt.Errorf("JSON document exceeds %d-byte limit", maxRelayJSONBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
