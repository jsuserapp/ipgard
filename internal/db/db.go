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

CREATE TABLE IF NOT EXISTS ip_stats (
	ip TEXT PRIMARY KEY,
	visit_count INTEGER NOT NULL DEFAULT 0,
	last_seen_at TEXT NOT NULL,
	freq_10min INTEGER NOT NULL DEFAULT 0,
	recent_events TEXT NOT NULL DEFAULT '[]',
	recent_paths TEXT NOT NULL DEFAULT '[]',
	blocked INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_stats_visit_count ON ip_stats(visit_count DESC);
CREATE INDEX IF NOT EXISTS idx_ip_stats_last_seen ON ip_stats(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_stats_freq ON ip_stats(freq_10min DESC);

CREATE TABLE IF NOT EXISTS global_stats (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	total_ips INTEGER NOT NULL DEFAULT 0,
	total_visits INTEGER NOT NULL DEFAULT 0,
	blocked_ips INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO global_stats (id, total_ips, total_visits, blocked_ips) VALUES (1, 0, 0, 0);

DROP TABLE IF EXISTS access_records;
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if err := s.migrateColumns(); err != nil {
		return err
	}
	return s.ensureGlobalStats()
}

func (s *Store) migrateColumns() error {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('ip_stats') WHERE name = 'location'`).Scan(&n)
	if n == 0 {
		if _, err := s.db.Exec(`ALTER TABLE ip_stats ADD COLUMN location TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add location column: %w", err)
		}
	}
	_, _ = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_ip_stats_blocked ON ip_stats(blocked)`)
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
