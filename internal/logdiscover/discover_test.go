package logdiscover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverLocalTestdata(t *testing.T) {
	// repo root when tests run from module root or package dir
	for _, base := range baseDirs() {
		logDir := filepath.Join(base, "testdata")
		if _, err := os.Stat(logDir); err != nil {
			continue
		}
		found := false
		for _, c := range Discover() {
			if filepath.Base(c.Path) == "access.log" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected testdata/access.log under %s in discover results", base)
		}
		return
	}
	t.Skip("testdata directory not found from test cwd")
}
