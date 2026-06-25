package firewall

import "errors"

var ErrNotSupported = errors.New("firewall not supported on this platform")

type Manager interface {
	Init() error
	Block(ip string) error
	Unblock(ip string) error
	Sync(ips []string) error
	ListRules() ([]string, error)
	Available() bool
}

func New(enabled bool, chain, iptablesPath string) Manager {
	return newPlatformManager(enabled, chain, iptablesPath)
}
