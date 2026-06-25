package firewall

import (
	"fmt"
	"net"
	"strings"
)

func ParseCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty cidr")
	}
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("invalid ipv4: %s", s)
		}
		return ip.String() + "/32", nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", fmt.Errorf("invalid cidr: %s", s)
	}
	if n.IP.To4() == nil {
		return "", fmt.Errorf("only ipv4 cidr supported")
	}
	return n.String(), nil
}
