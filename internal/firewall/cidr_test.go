package firewall

import "testing"

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"221.229.0.0/16", "221.229.0.0/16", true},
		{"221.229.173.0/24", "221.229.173.0/24", true},
		{"8.8.8.8", "8.8.8.8/32", true},
		{"", "", false},
		{"invalid", "", false},
	}
	for _, tc := range tests {
		got, err := ParseCIDR(tc.in)
		if tc.ok && err != nil {
			t.Fatalf("ParseCIDR(%q) unexpected err: %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("ParseCIDR(%q) expected err", tc.in)
		}
		if got != tc.want {
			t.Fatalf("ParseCIDR(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
