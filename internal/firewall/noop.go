//go:build !linux

package firewall

type noop struct{}

func newPlatformManager(enabled bool, chain, iptablesPath, cidrIpSet, ipsetPath string) Manager {
	return noop{}
}

func (noop) Init() error                              { return nil }
func (noop) Block(string) error                      { return ErrNotSupported }
func (noop) Unblock(string) error                    { return ErrNotSupported }
func (noop) UnblockRule(string, string, string) error { return ErrNotSupported }
func (noop) Sync([]string) error                     { return nil }
func (noop) ListBlockRules() ([]BlockRule, error)    { return nil, ErrNotSupported }
func (noop) AddCIDR(string) error                    { return ErrNotSupported }
func (noop) RemoveCIDR(string) error                 { return ErrNotSupported }
func (noop) SyncCIDRs([]string) error               { return nil }
func (noop) CIDRIpSetName() string                   { return "" }
func (noop) Available() bool                         { return false }
func (noop) CIDRSupported() bool                     { return false }
