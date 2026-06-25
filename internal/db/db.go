package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return nil, err
	}

	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS monitored_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	path TEXT NOT NULL UNIQUE,
	format TEXT NOT NULL DEFAULT 'auto',
	enabled INTEGER NOT NULL DEFAULT 1,
	file_offset INTEGER NOT NULL DEFAULT 0,
	file_inode INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_records (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ip TEXT NOT NULL,
	method TEXT,
	path TEXT,
	status INTEGER,
	bytes INTEGER,
	referer TEXT,
	user_agent TEXT,
	log_source TEXT NOT NULL,
	accessed_at TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_access_records_ip ON access_records(ip);
CREATE INDEX IF NOT EXISTS idx_access_records_accessed_at ON access_records(accessed_at);
CREATE INDEX IF NOT EXISTS idx_access_records_log_source ON access_records(log_source);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func (s *Store) GetSetting(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`
INSERT INTO settings (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value
`, key, value)
	return err
}

type MonitoredLog struct {
	ID         int64     `json:"id"`
	Path       string    `json:"path"`
	Format     string    `json:"format"`
	Enabled    bool      `json:"enabled"`
	FileOffset int64     `json:"file_offset"`
	FileInode  uint64    `json:"file_inode"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (s *Store) ListMonitoredLogs() ([]MonitoredLog, error) {
	rows, err := s.db.Query(`
SELECT id, path, format, enabled, file_offset, file_inode, created_at, updated_at
FROM monitored_logs ORDER BY id
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []MonitoredLog
	for rows.Next() {
		var m MonitoredLog
		var enabled int
		var created, updated string
		if err := rows.Scan(&m.ID, &m.Path, &m.Format, &enabled, &m.FileOffset, &m.FileInode, &created, &updated); err != nil {
			return nil, err
		}
		m.Enabled = enabled == 1
		m.CreatedAt, _ = time.Parse(time.RFC3339, created)
		m.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		list = append(list, m)
	}
	return list, rows.Err()
}

func (s *Store) AddMonitoredLog(path, format string) (*MonitoredLog, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`
INSERT INTO monitored_logs (path, format, enabled, file_offset, file_inode, created_at, updated_at)
VALUES (?, ?, 1, 0, 0, ?, ?)
`, path, format, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetMonitoredLog(id)
}

func (s *Store) GetMonitoredLog(id int64) (*MonitoredLog, error) {
	var m MonitoredLog
	var enabled int
	var created, updated string
	err := s.db.QueryRow(`
SELECT id, path, format, enabled, file_offset, file_inode, created_at, updated_at
FROM monitored_logs WHERE id = ?
`, id).Scan(&m.ID, &m.Path, &m.Format, &enabled, &m.FileOffset, &m.FileInode, &created, &updated)
	if err != nil {
		return nil, err
	}
	m.Enabled = enabled == 1
	m.CreatedAt, _ = time.Parse(time.RFC3339, created)
	m.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return &m, nil
}

func (s *Store) UpdateMonitoredLogState(id int64, offset int64, inode uint64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
UPDATE monitored_logs SET file_offset = ?, file_inode = ?, updated_at = ? WHERE id = ?
`, offset, inode, now, id)
	return err
}

func (s *Store) SetMonitoredLogEnabled(id int64, enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`UPDATE monitored_logs SET enabled = ?, updated_at = ? WHERE id = ?`, val, now, id)
	return err
}

func (s *Store) DeleteMonitoredLog(id int64) error {
	_, err := s.db.Exec(`DELETE FROM monitored_logs WHERE id = ?`, id)
	return err
}

type AccessRecord struct {
	ID         int64     `json:"id"`
	IP         string    `json:"ip"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	Bytes      int64     `json:"bytes"`
	Referer    string    `json:"referer"`
	UserAgent  string    `json:"user_agent"`
	LogSource  string    `json:"log_source"`
	AccessedAt time.Time `json:"accessed_at"`
	CreatedAt  time.Time `json:"created_at"`
}

type RecordFilter struct {
	IP        string
	LogSource string
	Limit     int
	Offset    int
}

func (s *Store) InsertAccessRecord(r *AccessRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`
INSERT INTO access_records (ip, method, path, status, bytes, referer, user_agent, log_source, accessed_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, r.IP, r.Method, r.Path, r.Status, r.Bytes, r.Referer, r.UserAgent, r.LogSource,
		r.AccessedAt.UTC().Format(time.RFC3339), now)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) ListAccessRecords(f RecordFilter) ([]AccessRecord, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}

	where := "WHERE 1=1"
	args := []any{}
	if f.IP != "" {
		where += " AND ip LIKE ?"
		args = append(args, "%"+f.IP+"%")
	}
	if f.LogSource != "" {
		where += " AND log_source = ?"
		args = append(args, f.LogSource)
	}

	var total int
	countArgs := append([]any{}, args...)
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM access_records `+where, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
SELECT id, ip, method, path, status, bytes, referer, user_agent, log_source, accessed_at, created_at
FROM access_records ` + where + ` ORDER BY accessed_at DESC LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []AccessRecord
	for rows.Next() {
		var r AccessRecord
		var accessed, created string
		if err := rows.Scan(&r.ID, &r.IP, &r.Method, &r.Path, &r.Status, &r.Bytes, &r.Referer, &r.UserAgent, &r.LogSource, &accessed, &created); err != nil {
			return nil, 0, err
		}
		r.AccessedAt, _ = time.Parse(time.RFC3339, accessed)
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		list = append(list, r)
	}
	return list, total, rows.Err()
}

type IPStat struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

func (s *Store) TopIPs(limit int) ([]IPStat, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`
SELECT ip, COUNT(*) AS cnt FROM access_records
GROUP BY ip ORDER BY cnt DESC LIMIT ?
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make([]IPStat, 0)
	for rows.Next() {
		var st IPStat
		if err := rows.Scan(&st.IP, &st.Count); err != nil {
			return nil, err
		}
		stats = append(stats, st)
	}
	return stats, rows.Err()
}

func (s *Store) RecordCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM access_records`).Scan(&n)
	return n, err
}
