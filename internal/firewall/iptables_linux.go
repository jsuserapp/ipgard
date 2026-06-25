//go:build linux

package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
)

const filterTable = "filter"

type ipTables struct {
	enabled      bool
	chain        string
	iptablesPath string
}

func newPlatformManager(enabled bool, chain, iptablesPath string) Manager {
	if chain == "" {
		chain = "IPGARD"
	}
	if iptablesPath == "" {
		iptablesPath = "iptables"
	}
	return &ipTables{enabled: enabled, chain: chain, iptablesPath: iptablesPath}
}

func (f *ipTables) Available() bool {
	if !f.enabled {
		return false
	}
	_, err := exec.LookPath(f.iptablesPath)
	return err == nil
}

func (f *ipTables) Init() error {
	if !f.Available() {
		return nil
	}
	if err := f.ensureChain(filterTable, f.chain); err != nil {
		return err
	}
	return f.ensureJump(filterTable, "INPUT", f.chain)
}

// ListBlockRules reads all source-based DROP/REJECT rules from the system filter table.
func (f *ipTables) ListBlockRules() ([]BlockRule, error) {
	if !f.Available() {
		return nil, ErrNotSupported
	}

	out, err := f.output("-t", filterTable, "-S")
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var rules []BlockRule
	for _, line := range strings.Split(out, "\n") {
		r, ok := parseBlockRuleLine(line)
		if !ok {
			continue
		}
		key := r.Chain + "\x00" + r.IP + "\x00" + r.Action
		if seen[key] {
			continue
		}
		seen[key] = true
		rules = append(rules, r)
	}

	if len(rules) == 0 {
		if out, err := f.output("-t", filterTable, "-L", "-n"); err == nil {
			rules = parseAllListRules(out)
		}
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Chain != rules[j].Chain {
			return rules[i].Chain < rules[j].Chain
		}
		if rules[i].IP != rules[j].IP {
			return rules[i].IP < rules[j].IP
		}
		return rules[i].Action < rules[j].Action
	})
	return rules, nil
}

func parseBlockRuleLine(line string) (BlockRule, bool) {
	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) < 4 || fields[0] != "-A" {
		return BlockRule{}, false
	}

	action := ""
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "-j" {
			action = strings.ToUpper(fields[i+1])
			break
		}
	}
	if action != "DROP" && action != "REJECT" {
		return BlockRule{}, false
	}

	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "-s" {
			if ip := normalizeRuleIP(fields[i+1]); ip != "" {
				return BlockRule{IP: ip, Chain: fields[1], Action: action}, true
			}
		}
	}
	return BlockRule{}, false
}

func parseAllListRules(out string) []BlockRule {
	var rules []BlockRule
	seen := map[string]bool{}
	chain := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Chain ") {
			chain = strings.Fields(line)[1]
			continue
		}
		if chain == "" || line == "" || strings.HasPrefix(line, "target") || strings.HasPrefix(line, "pkts") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		action := strings.ToUpper(fields[0])
		if action != "DROP" && action != "REJECT" {
			continue
		}
		src := fields[5]
		ip := normalizeRuleIP(src)
		if ip == "" {
			continue
		}
		r := BlockRule{IP: ip, Chain: chain, Action: action}
		key := r.Chain + "\x00" + r.IP + "\x00" + r.Action
		if seen[key] {
			continue
		}
		seen[key] = true
		rules = append(rules, r)
	}
	return rules
}

func normalizeRuleIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0.0.0.0/0" || strings.EqualFold(s, "anywhere") {
		return ""
	}
	if strings.Contains(s, "/") {
		if ip, _, err := net.ParseCIDR(s); err == nil && ip != nil {
			return ip.String()
		}
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

func (f *ipTables) Block(ip string) error {
	if !f.Available() {
		return ErrNotSupported
	}
	if err := validateIP(ip); err != nil {
		return err
	}
	if f.hasRuleInChain(f.chain, ip, "DROP") {
		return nil
	}
	return f.run("-t", filterTable, "-A", f.chain, "-s", ip, "-j", "DROP")
}

// Unblock removes the IP only from this app's managed chain.
func (f *ipTables) Unblock(ip string) error {
	return f.UnblockRule(f.chain, ip, "DROP")
}

func (f *ipTables) UnblockRule(chain, ip, action string) error {
	if !f.Available() {
		return ErrNotSupported
	}
	if err := validateIP(ip); err != nil {
		return err
	}
	action = strings.ToUpper(strings.TrimSpace(action))
	if action == "" {
		action = "DROP"
	}
	for f.hasRuleInChain(chain, ip, action) {
		if err := f.run("-t", filterTable, "-D", chain, "-s", ip, "-j", action); err != nil {
			return err
		}
	}
	return nil
}

func (f *ipTables) Sync(ips []string) error {
	if !f.Available() {
		return nil
	}
	if err := f.Init(); err != nil {
		return err
	}
	for _, ip := range ips {
		if err := f.Block(ip); err != nil {
			return err
		}
	}
	return nil
}

func (f *ipTables) ensureChain(table, chain string) error {
	check := exec.Command(f.iptablesPath, "-t", table, "-L", chain, "-n")
	if err := check.Run(); err == nil {
		return nil
	}
	return f.run("-t", table, "-N", chain)
}

func (f *ipTables) ensureJump(table, baseChain, targetChain string) error {
	out, err := f.output("-t", table, "-S", baseChain)
	if err != nil {
		return err
	}
	needle := "-j " + targetChain
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return nil
		}
	}
	return f.run("-t", table, "-I", baseChain, "1", "-j", targetChain)
}

func (f *ipTables) hasRuleInChain(chain, ip, action string) bool {
	out, err := f.output("-t", filterTable, "-S", chain)
	if err != nil {
		return false
	}
	action = strings.ToUpper(action)
	needleIP := "-s " + ip
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A "+chain+" ") && line != "-A "+chain {
			continue
		}
		if !strings.Contains(line, needleIP) {
			continue
		}
		if strings.Contains(strings.ToUpper(line), " "+action) {
			return true
		}
	}
	return false
}

func (f *ipTables) output(args ...string) (string, error) {
	cmd := exec.Command(f.iptablesPath, args...)
	out, err := cmd.Output()
	if err != nil {
		if len(out) > 0 {
			return "", fmt.Errorf("iptables %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return "", fmt.Errorf("iptables %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func (f *ipTables) run(args ...string) error {
	cmd := exec.Command(f.iptablesPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid ip: %s", ip)
	}
	return nil
}
