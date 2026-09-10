package dero

import "testing"

func TestValidateAddress(t *testing.T) {
	valid := "dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq"
	if got, err := ValidateAddress(valid); err != nil || got != valid {
		t.Fatalf("valid address: got %q err=%v", got, err)
	}
	for _, bad := range []string{
		"",
		"dero1abc",
		"deto1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq",
		"dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pna",
	} {
		if _, err := ValidateAddress(bad); err == nil {
			t.Fatalf("accepted invalid address %q", bad)
		}
	}
}
