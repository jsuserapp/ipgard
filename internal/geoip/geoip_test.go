package geoip

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFormatRegion(t *testing.T) {
	got := FormatRegion("中国|0|浙江省|杭州市|电信")
	want := "中国 浙江省 杭州市 电信"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLookupIP2Region(t *testing.T) {
	paths := []string{
		DefaultV4DB,
		filepath.Join("..", "..", "data", "ip2region_v4.xdb"),
	}
	var dbPath string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			dbPath = p
			break
		}
	}
	if dbPath == "" {
		t.Skip("ip2region_v4.xdb not found in data/")
	}

	r, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if !r.Available() {
		t.Fatal("resolver not available")
	}

	loc := r.Lookup("114.114.114.114")
	if loc == "" {
		t.Fatal("expected location for 114.114.114.114")
	}
	t.Logf("114.114.114.114 => %s", loc)

	loc = r.Lookup("127.0.0.1")
	if loc != "内网" {
		t.Fatalf("127.0.0.1 => %q, want 内网", loc)
	}

	// cache hit
	if r.Lookup("114.114.114.114") == "" {
		t.Fatal("cache miss on second lookup")
	}

	if r.Lookup("2001:4860:4860::8888") != "" {
		t.Fatal("IPv6 should be skipped when using v4 db only")
	}
}

func TestResolveDBPath(t *testing.T) {
	if _, err := os.Stat(DefaultV4DB); err != nil {
		t.Skip("v4 db not present")
	}
	got := ResolveDBPath("./data/missing.xdb")
	if got != DefaultV4DB {
		t.Fatalf("expected fallback to %s, got %s", DefaultV4DB, got)
	}
}
