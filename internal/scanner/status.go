package scanner

import (
	"sync"
	"time"
)

// Status is a snapshot of the background log scanner.
type Status struct {
	Scanning    bool      `json:"scanning"`
	CurrentPath string    `json:"current_path,omitempty"`
	FileIndex   int       `json:"file_index"`
	FileCount   int       `json:"file_count"`
	BytesRead   int64     `json:"bytes_read"`
	BytesTotal  int64     `json:"bytes_total"`
	StartedAt   time.Time `json:"started_at,omitempty"`
}

func (st Status) Progress() float64 {
	if st.BytesTotal <= 0 {
		return 0
	}
	p := float64(st.BytesRead) / float64(st.BytesTotal) * 100
	if p > 100 {
		return 100
	}
	if p < 0 {
		return 0
	}
	return p
}

type statusTracker struct {
	mu   sync.RWMutex
	data Status
}

func newStatusTracker() *statusTracker {
	return &statusTracker{}
}

func (t *statusTracker) Snapshot() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.data
}

func (t *statusTracker) beginScan(fileCount int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data = Status{
		Scanning:  true,
		FileCount: fileCount,
		StartedAt: time.Now().UTC(),
	}
}

func (t *statusTracker) endScan() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data = Status{}
}

func (t *statusTracker) setFile(index int, path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data.FileIndex = index
	t.data.CurrentPath = path
	t.data.BytesRead = 0
	t.data.BytesTotal = 0
}

func (t *statusTracker) setBytesTotal(bytesTotal int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data.BytesTotal = bytesTotal
	t.data.BytesRead = 0
}

func (t *statusTracker) setProgress(bytesRead int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data.BytesRead = bytesRead
}
