package db

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecordVisitsBatch(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC()
	err = store.RecordVisitsBatch(map[string][]Visit{
		"1.2.3.4": {
			{Path: "/a", At: now},
			{Path: "/b", At: now.Add(time.Minute)},
		},
		"5.6.7.8": {
			{Path: "/c", At: now},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	row, err := store.GetIPStat("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if row.VisitCount != 2 {
		t.Fatalf("visit_count: got %d", row.VisitCount)
	}
	if len(row.RecentPaths) != 2 {
		t.Fatalf("recent_paths: got %d", len(row.RecentPaths))
	}
	if row.RecentPaths[0].Path != "/b" {
		t.Fatalf("expected latest path /b, got %s", row.RecentPaths[0].Path)
	}

	if err := store.SetIPBlocked("1.2.3.4", true); err != nil {
		t.Fatal(err)
	}
	row, _ = store.GetIPStat("1.2.3.4")
	if !row.Blocked {
		t.Fatal("expected blocked")
	}

	// further visits preserve blocked
	err = store.RecordVisitsBatch(map[string][]Visit{
		"1.2.3.4": {{Path: "/d", At: now.Add(2 * time.Minute)}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	row, _ = store.GetIPStat("1.2.3.4")
	if !row.Blocked || row.VisitCount != 3 {
		t.Fatalf("blocked=%v count=%d", row.Blocked, row.VisitCount)
	}

	totalIPs, blockedIPs, totalVisits, err := store.IPStatsSummary()
	if err != nil {
		t.Fatal(err)
	}
	if totalIPs != 2 || blockedIPs != 1 || totalVisits != 4 {
		t.Fatalf("summary: ips=%d blocked=%d visits=%d", totalIPs, blockedIPs, totalVisits)
	}
}
