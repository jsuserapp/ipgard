package geoip

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

const DefaultV4DB = "./data/ip2region_v4.xdb"

type Resolver interface {
	Lookup(ip string) string
	Available() bool
	Warm(map[string]string)
	Close()
}

type noop struct{}

func (noop) Lookup(string) string       { return "" }
func (noop) Available() bool            { return false }
func (noop) Warm(map[string]string)     {}
func (noop) Close()                     {}

type ip2region struct {
	searcher *xdb.Searcher
	cache    sync.Map
}

func Open(dbPath string) (Resolver, error) {
	dbPath = ResolveDBPath(dbPath)
	header, err := xdb.LoadHeaderFromFile(dbPath)
	if err != nil {
		return nil, err
	}
	version, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, err
	}
	buf, err := xdb.LoadContentFromFile(dbPath)
	if err != nil {
		return nil, err
	}
	searcher, err := xdb.NewWithBuffer(version, buf)
	if err != nil {
		return nil, err
	}
	return &ip2region{searcher: searcher}, nil
}

func ResolveDBPath(path string) string {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		dir := filepath.Dir(path)
		if dir == "." {
			dir = "data"
		}
		for _, name := range []string{"ip2region_v4.xdb", "ip2region.xdb"} {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	for _, p := range []string{DefaultV4DB, "./data/ip2region.xdb"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return path
}

func NewOptional(enabled bool, dbPath string) Resolver {
	if !enabled {
		return noop{}
	}
	dbPath = ResolveDBPath(dbPath)
	if dbPath == "" {
		return noop{}
	}
	r, err := Open(dbPath)
	if err != nil {
		return noop{}
	}
	return r
}

func (r *ip2region) Warm(locations map[string]string) {
	for ip, loc := range locations {
		r.cache.Store(ip, loc)
	}
}

func (r *ip2region) Lookup(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if v, ok := r.cache.Load(ip); ok {
		return v.(string)
	}
	loc := r.resolve(ip)
	r.cache.Store(ip, loc)
	return loc
}

func (r *ip2region) resolve(ip string) string {
	if isIPv6(ip) {
		return ""
	}
	if loc := privateLabel(ip); loc != "" {
		return loc
	}
	raw, err := r.searcher.Search(ip)
	if err != nil {
		return ""
	}
	return FormatRegion(raw)
}

func (r *ip2region) Available() bool { return r.searcher != nil }

func (r *ip2region) Close() {
	if r.searcher != nil {
		r.searcher.Close()
	}
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	return parsed != nil && parsed.To4() == nil
}

func privateLabel(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return "内网"
	}
	return ""
}

func FormatRegion(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "|")
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "0" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return strings.Join(out, " ")
}
