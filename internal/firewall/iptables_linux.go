//go:build linux

package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

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
	if err := f.ensureChain("filter", f.chain); err != nil {
		return err
	}
	return f.ensureJump("filter", "INPUT", f.chain)
}

func (f *ipTables) ListRules() ([]string, error) {
	if !f.Available() {
		return nil, ErrNotSupported
	}
	out, err := exec.Command(f.iptablesPath, "-S", f.chain).Output()
	if err != nil {
		return nil, fmt.Errorf("iptables -S %s: %w", f.chain, err)
	}
	var ips []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		ip := parseDropRuleIP(line)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	return ips, nil
}

func parseDropRuleIP(line string) string {
	fields := strings.Fields(line)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "-s" {
			ip := strings.TrimSuffix(fields[i+1], "/32")
			ip = strings.TrimSuffix(ip, "/128")
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
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
	if f.hasRule(ip) {
		return nil
	}
	return f.run("-A", f.chain, "-s", ip, "-j", "DROP")
}

func (f *ipTables) Unblock(ip string) error {
	if !f.Available() {
		return ErrNotSupported
	}
	if err := validateIP(ip); err != nil {
		return err
	}
	for f.hasRule(ip) {
		if err := f.run("-D", f.chain, "-s", ip, "-j", "DROP"); err != nil {
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
	out, err := exec.Command(f.iptablesPath, "-t", table, "-S", baseChain).Output()
	if err != nil {
		return err
	}
 needle := fmt.Sprintf("-j %s", targetChain)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, needle) {
			return nil
		}
	}
	return f.run("-t", table, "-I", baseChain, "1", "-j", targetChain)
}

func (f *ipTables) hasRule(ip string) bool {
	out, err := exec.Command(f.iptablesPath, "-S", f.chain).Output()
	if err != nil {
		return false
	}
	needle := fmt.Sprintf("-s %s -j DROP", ip)
	return strings.Contains(string(out), needle)
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
