package firewall

import "errors"

var ErrNotSupported = errors.New("firewall not supported on this platform")

// BlockRule is a source-IP DROP/REJECT rule read from the system iptables filter table.
type BlockRule struct {
	IP     string `json:"ip"`
	Chain  string `json:"chain"`
	Action string `json:"action"`
}

type Manager interface {
	Init() error
	Block(ip string) error
	Unblock(ip string) error
	UnblockRule(chain, ip, action string) error
	Sync(ips []string) error
	ListBlockRules() ([]BlockRule, error)
	Available() bool
}

func New(enabled bool, chain, iptablesPath string) Manager {
	return newPlatformManager(enabled, chain, iptablesPath)
}
