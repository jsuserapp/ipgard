//go:build linux

package firewall

import "testing"

func TestParseBlockRuleLine_multiChain(t *testing.T) {
	lines := []string{
		"-A INPUT -s 136.243.220.212 -j DROP",
		"-A IPGARD -s 17.22.245.55 -j DROP",
		"-A f2b-http-get-dos -s 221.229.173.221 -j REJECT --reject-with icmp-port-unreachable",
		"-A INPUT -j IPGARD",
	}
	want := []BlockRule{
		{IP: "136.243.220.212", Chain: "INPUT", Action: "DROP"},
		{IP: "17.22.245.55", Chain: "IPGARD", Action: "DROP"},
		{IP: "221.229.173.221", Chain: "f2b-http-get-dos", Action: "REJECT"},
	}
	var got []BlockRule
	for _, line := range lines {
		if r, ok := parseBlockRuleLine(line); ok {
			got = append(got, r)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rule %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseBlockRuleLine(t *testing.T) {
	tests := []struct {
		line string
		want BlockRule
		ok   bool
	}{
		{"-A IPGARD -s 1.2.3.4 -j DROP", BlockRule{IP: "1.2.3.4", Chain: "IPGARD", Action: "DROP"}, true},
		{"-A INPUT -s 10.0.0.8/32 -j REJECT", BlockRule{IP: "10.0.0.8", Chain: "INPUT", Action: "REJECT"}, true},
		{"-A INPUT -j IPGARD", BlockRule{}, false},
		{"-A INPUT -s 1.2.3.4 -j ACCEPT", BlockRule{}, false},
	}
	for _, tc := range tests {
		got, ok := parseBlockRuleLine(tc.line)
		if ok != tc.ok {
			t.Fatalf("parseBlockRuleLine(%q) ok=%v, want %v", tc.line, ok, tc.ok)
		}
		if got != tc.want {
			t.Fatalf("parseBlockRuleLine(%q) = %+v, want %+v", tc.line, got, tc.want)
		}
	}
}

func TestParseAllListRules(t *testing.T) {
	out := `Chain INPUT (policy ACCEPT)
target     prot opt in     out     source               destination
DROP       all  --  *      *       203.0.113.9          0.0.0.0/0
Chain IPGARD (1 references)
target     prot opt opt in     out     source               destination
REJECT     all  --  *      *       198.51.100.4         0.0.0.0/0
`
	rules := parseAllListRules(out)
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2: %#v", len(rules), rules)
	}
}
