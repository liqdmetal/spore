package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// provision creates the server-side blind mailbox materials for one hosted
// user. It does not generate or receive the user's identity private keys.
// The user's device must run `spore init`; this command creates only mailbox,
// bearer-token, notification routing, and public prekey delivery material.
func provisioncmd(args []string) {
	fs := flag.NewFlagSet("provision", flag.ExitOnError)
	users := fs.String("users", "", "hosted users directory")
	name := fs.String("name", "", "user route name")
	tokens := fs.String("tokens", "", "bearer token JSON map (created/updated securely)")
	notifyFile := fs.String("notify-file", "", "non-secret notification routing JSON map")
	batch := fs.String("batch", "", "public prekey batch JSON from the user's device")
	mailboxURL := fs.String("mailbox-url", "", "public user mailbox URL, for the onboarding record")
	address := fs.String("address", "", "user chain address, for the onboarding record")
	pinnedSig := fs.String("pinned-sig", "", "user pinned signing public key, for the onboarding record")
	email := fs.String("email", "", "notification email address")
	sms := fs.String("sms", "", "notification SMS E.164 number")
	webhook := fs.String("webhook", "", "notification webhook URL")
	token := fs.String("token", "", "bearer token; omit to generate one")
	force := fs.Bool("force", false, "replace existing token/mailbox metadata")
	_ = fs.Parse(args)
	if *users == "" || *name == "" || *tokens == "" || *batch == "" {
		check(errors.New("provision requires -users DIR -name USER -tokens FILE -batch PUBLIC_BATCH.json"))
	}
	if !validUserName(*name) {
		check(fmt.Errorf("provision: invalid user name %q", *name))
	}
	if filepath.Base(*name) != *name {
		check(errors.New("provision: user name must be one path segment"))
	}
	userDir := filepath.Join(*users, *name)
	if _, err := os.Stat(userDir); err == nil && !*force {
		check(fmt.Errorf("%s already exists; use -force to replace metadata", userDir))
	}
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		check(err)
	}
	if _, err := loadPublicBatch(*batch); err != nil {
		check(err)
	}
	if *token == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			check(err)
		}
		*token = hex.EncodeToString(b)
	}
	tokMap, err := loadHostTokens(*tokens)
	if err != nil && !os.IsNotExist(err) {
		check(err)
	}
	if tokMap == nil {
		tokMap = map[string]string{}
	}
	if _, exists := tokMap[*name]; exists && !*force {
		check(fmt.Errorf("token for %s already exists; use -force to replace it", *name))
	}
	tokMap[*name] = *token
	writeJSON0600(*tokens, tokMap)
	batchRaw, err := os.ReadFile(*batch)
	check(err)
	// Mailbox.Open loads this exact filename. The source batch remains on the
	// device; the hosted copy contains public bundles only.
	if err := os.WriteFile(filepath.Join(userDir, "prekey-batch.json"), batchRaw, 0o600); err != nil {
		check(err)
	}
	if *notifyFile != "" {
		if err := writeMailboxNotifyConfig(*notifyFile, *name, mailboxNotifySpec{Email: *email, SMS: *sms, Webhook: *webhook}); err != nil {
			check(err)
		}
	}
	card := map[string]string{"name": *name, "mailbox_url": strings.TrimRight(*mailboxURL, "/"), "mailbox_route": "/u/" + *name, "prekey_route": "/u/" + *name + "/prekey", "body_route": "/u/" + *name + "/put/<cid>", "address": *address, "pinned_sig": *pinnedSig, "token": *token}
	writeJSON0600(filepath.Join(userDir, "onboarding.json"), card)
	fmt.Printf("provisioned hosted mailbox %s\n", *name)
	fmt.Printf("  mailbox dir: %s\n", userDir)
	fmt.Printf("  token file:  %s\n", *tokens)
	fmt.Printf("  onboarding:  %s (0600; contains the bearer token)\n", filepath.Join(userDir, "onboarding.json"))
	fmt.Printf("  public URL:  %s/u/%s\n", strings.TrimRight(*mailboxURL, "/"), *name)
	fmt.Println("  bearer token was not printed; deliver it through a separate secure channel")
}

func loadPublicBatch(path string) ([]ratchet.SPKBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v struct {
		Bundles []ratchet.SPKBundle `json:"bundles"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("batch JSON: %w", err)
	}
	if len(v.Bundles) == 0 {
		return nil, errors.New("batch contains no public bundles")
	}
	return v.Bundles, nil
}

func writeJSON0600(path string, v any) {
	raw, err := json.MarshalIndent(v, "", "  ")
	check(err)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		check(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		check(err)
	}
}

// Keep ratchetwire imported here as a compile-time reminder that provisioning
// handles public prekey material, not the private OPK pool.
var _ = ratchetwire.PointerV1
