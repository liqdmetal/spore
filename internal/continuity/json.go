package continuity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// decodeStrict decodes exactly one JSON value and rejects unknown fields,
// duplicate object keys, and trailing values. Continuity artifacts are
// signed/committed protocol objects; silently accepting ambiguous JSON creates
// a gap between what an operator inspected and what a verifier consumed.
func decodeStrict(raw []byte, dst any) error {
	return decodeStrictLimit(raw, dst, MaxArtifactBytes)
}

func decodeStrictLimit(raw []byte, dst any, maxBytes int) error {
	if maxBytes <= 0 || len(raw) > maxBytes {
		return ErrArtifactTooLarge
	}
	if err := validateJSONStructure(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return errors.New("continuity: trailing JSON value")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// validateJSONStructure walks a JSON value with the token API so duplicate
// object keys are rejected before encoding/json applies last-value-wins rules.
func validateJSONStructure(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, err := dec.Token()
	if err != nil {
		return err
	}
	if err := walkJSONToken(dec, first); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("continuity: trailing JSON value")
		}
		return err
	}
	return nil
}

func walkJSONToken(dec *json.Decoder, tok json.Token) error {
	return walkJSONTokenDepth(dec, tok, 1)
}

func walkJSONTokenDepth(dec *json.Decoder, tok json.Token, depth int) error {
	if depth > MaxJSONDepth {
		return ErrArtifactTooLarge
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("continuity: JSON object key is not a string")
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("continuity: duplicate JSON object key %q", name)
			}
			seen[name] = struct{}{}
			value, err := dec.Token()
			if err != nil {
				return err
			}
			if err := walkJSONTokenDepth(dec, value, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("continuity: malformed JSON object")
		}
	case '[':
		for dec.More() {
			value, err := dec.Token()
			if err != nil {
				return err
			}
			if err := walkJSONTokenDepth(dec, value, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("continuity: malformed JSON array")
		}
	default:
		return errors.New("continuity: malformed JSON delimiter")
	}
	return nil
}
