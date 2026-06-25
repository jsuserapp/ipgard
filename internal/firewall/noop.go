//go:build !linux

package firewall

type noop struct{}

func newPlatformManager(enabled bool, chain, iptablesPath string) Manager {
	return noop{}
}

func (noop) Init() error              { return nil }
func (noop) Block(string) error       { return ErrNotSupported }
func (noop) Unblock(string) error     { return ErrNotSupported }
func (noop) Sync([]string) error      { return nil }
func (noop) ListRules() ([]string, error) { return nil, ErrNotSupported }
func (noop) Available() bool          { return false }
