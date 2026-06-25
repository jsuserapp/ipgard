package scanner

import (
	"bufio"
	"context"
	"os"
	"time"

	"ipgard/internal/db"
	"ipgard/internal/geoip"
	"ipgard/internal/parser"
)

const batchFlushLines = 5000

type Scanner struct {
	store    *db.Store
	geo      geoip.Resolver
	interval time.Duration
	status   *statusTracker
}

func New(store *db.Store, geo geoip.Resolver, interval time.Duration) *Scanner {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if geo == nil {
		geo = geoip.NewOptional(false, "")
	}
	return &Scanner{
		store:    store,
		geo:      geo,
		interval: interval,
		status:   newStatusTracker(),
	}
}

func (s *Scanner) Status() Status {
	return s.status.Snapshot()
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
	enabled := make([]db.MonitoredLog, 0, len(logs))
	for _, log := range logs {
		if log.Enabled {
			enabled = append(enabled, log)
		}
	}
	if len(enabled) == 0 {
		return
	}

	s.status.beginScan(len(enabled))
	defer s.status.endScan()

	for i, log := range enabled {
		s.status.setFile(i+1, log.Path)
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

	bytesTotal := info.Size() - offset
	s.status.setBytesTotal(bytesTotal)

	if _, err := f.Seek(offset, 0); err != nil {
		return err
	}

	format := m.Format
	if format == "" || format == "auto" {
		format = "auto"
	}

	batch := make(map[string][]db.Visit)
	lineCount := 0
	reader := bufio.NewReader(f)

	lookup := func(ip string) string {
		if s.geo == nil || !s.geo.Available() {
			return ""
		}
		return s.geo.Lookup(ip)
	}

	flush := func() {
		if len(batch) == 0 {
			return
		}
		_ = s.store.RecordVisitsBatch(batch, lookup)
		batch = make(map[string][]db.Visit)
		lineCount = 0
		if pos, err := f.Seek(0, 1); err == nil {
			s.status.setProgress(pos - offset)
		}
	}

	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			entry, _ := parser.ParseLine(line, format)
			if entry != nil {
				batch[entry.IP] = append(batch[entry.IP], db.Visit{
					Path: entry.Path,
					At:   entry.Time,
				})
				lineCount++
				if lineCount >= batchFlushLines {
					flush()
				}
			}
		}
		if err != nil {
			break
		}
	}
	flush()

	newOffset, _ := f.Seek(0, 1)
	s.status.setProgress(newOffset - offset)
	return s.store.UpdateMonitoredLogState(m.ID, newOffset, inode)
}
