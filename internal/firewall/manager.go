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
	AddCIDR(cidr string) error
	RemoveCIDR(cidr string) error
	SyncCIDRs(cidrs []string) error
	CIDRIpSetName() string
	Available() bool
	CIDRSupported() bool
}

func New(enabled bool, chain, iptablesPath, cidrIpSet, ipsetPath string) Manager {
	return newPlatformManager(enabled, chain, iptablesPath, cidrIpSet, ipsetPath)
}
