package scanner

import (
	"bufio"
	"context"
	"os"
	"time"

	"ipgard/internal/db"
	"ipgard/internal/parser"
)

type Scanner struct {
	store    *db.Store
	interval time.Duration
}

func New(store *db.Store, interval time.Duration) *Scanner {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &Scanner{store: store, interval: interval}
}

func (s *Scanner) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.scanOnce()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scanOnce()
		}
	}
}

func (s *Scanner) scanOnce() {
	logs, err := s.store.ListMonitoredLogs()
	if err != nil {
		return
	}
	for _, log := range logs {
		if !log.Enabled {
			continue
		}
		_ = s.scanFile(&log)
	}
}

func (s *Scanner) scanFile(m *db.MonitoredLog) error {
	f, err := os.Open(m.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	inode := fileInode(info)
	offset := m.FileOffset

	if inode != 0 && m.FileInode != 0 && inode != m.FileInode {
		offset = 0
	}
	if info.Size() < offset {
		offset = 0
	}

	if _, err := f.Seek(offset, 0); err != nil {
		return err
	}

	format := m.Format
	if format == "" || format == "auto" {
		format = "auto"
	}

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			entry, _ := parser.ParseLine(line, format)
			if entry != nil {
				rec := &db.AccessRecord{
					IP:         entry.IP,
					Method:     entry.Method,
					Path:       entry.Path,
					Status:     entry.Status,
					Bytes:      entry.Bytes,
					Referer:    entry.Referer,
					UserAgent:  entry.UserAgent,
					LogSource:  m.Path,
					AccessedAt: entry.Time,
				}
				_ = s.store.InsertAccessRecord(rec)
			}
		}
		if err != nil {
			break
		}
	}

	newOffset, _ := f.Seek(0, 1)
	return s.store.UpdateMonitoredLogState(m.ID, newOffset, inode)
}
