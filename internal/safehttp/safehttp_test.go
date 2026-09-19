package safehttp

import "testing"

func TestHostIsLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:19292", true},
		{"127.0.0.1", true},
		{"localhost:19191", true},
		{"LOCALHOST:1", true},
		{"[::1]:8099", true},
		{"::1", true},
		{":19292", false},         // bare :port = all interfaces
		{"0.0.0.0:19292", false},  // all interfaces
		{"[::]:19292", false},     // all interfaces (ipv6)
		{"example.com:80", false}, // empty token → refused
		{"10.0.0.5:19292", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := HostIsLoopback(tc.addr); got != tc.want {
			t.Errorf("HostIsLoopback(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestCheckBind(t *testing.T) {
	// Loopback binds are always fine, token or not.
	for _, addr := range []string{"127.0.0.1:19292", "localhost:1", "[::1]:80"} {
		if err := CheckBind(addr, "", "mailbox"); err != nil {
			t.Errorf("CheckBind(%q, no token) = %v, want nil", addr, err)
		}
		if err := CheckBind(addr, "sekrit", "mailbox"); err != nil {
			t.Errorf("CheckBind(%q, token) = %v, want nil", addr, err)
		}
	}
	// Non-loopback without a token must be REFUSED (audit C1/C2/C3).
	for _, addr := range []string{":19292", "0.0.0.0:19292", "10.0.0.5:19292", "example.com:80"} {
		err := CheckBind(addr, "", "mailbox")
		if err == nil {
			t.Errorf("CheckBind(%q, no token) = nil, want refusal", addr)
		}
		// Blank/whitespace tokens don't count.
		if err := CheckBind(addr, "   ", "mailbox"); err == nil {
			t.Errorf("CheckBind(%q, blank token) = nil, want refusal", addr)
		}
		// With a token, the bind may proceed.
		if err := CheckBind(addr, "sekrit", "mailbox"); err != nil {
			t.Errorf("CheckBind(%q, token) = %v, want nil", addr, err)
		}
	}
}
