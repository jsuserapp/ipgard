package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	maxRecentPaths = 100
	freqWindow     = 10 * time.Minute
)

type RecentPath struct {
	Path string    `json:"path"`
	At   time.Time `json:"at"`
}

type RecentEvent struct {
	At   time.Time `json:"at"`
	Path string    `json:"path"`
}

type Visit struct {
	Path string
	At   time.Time
}

type IPStatRow struct {
	IP          string       `json:"ip"`
	Location    string       `json:"location"`
	VisitCount  int          `json:"visit_count"`
	LastSeenAt  time.Time    `json:"last_seen_at"`
	Freq10Min   int          `json:"freq_10min"`
	RecentPaths []RecentPath `json:"recent_paths"`
	Blocked     bool         `json:"blocked"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type IPFilter struct {
	IP        string
	Blocked   *bool
	Sort      string // visit_count, last_seen, freq_10min
	Limit     int
	Offset    int
	SkipTotal bool
}

func (s *Store) IPLocationIndex() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT ip, location FROM ip_stats WHERE location != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var ip, loc string
		if err := rows.Scan(&ip, &loc); err != nil {
			return nil, err
		}
		out[ip] = loc
	}
	return out, rows.Err()
}

func (s *Store) RecordVisitsBatch(visits map[string][]Visit, lookup func(ip string) string) error {
	if len(visits) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	ips := make([]string, 0, len(visits))
	for ip := range visits {
		ips = append(ips, ip)
	}
	existing, err := s.loadIPStatsTx(tx, ips)
	if err != nil {
		return err
	}

	var deltaIPs, deltaVisits int
	for ip, events := range visits {
		wasNew := existing[ip] == nil
		if err := s.applyVisitsTx(tx, ip, events, existing[ip], lookup); err != nil {
			return err
		}
		deltaVisits += len(events)
		if wasNew {
			deltaIPs++
		}
	}
	if err := s.adjustGlobalStatsTx(tx, deltaIPs, deltaVisits, 0); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) applyVisitsTx(tx *sql.Tx, ip string, events []Visit, row *ipStatInternal, lookup func(ip string) string) error {
	if len(events) == 0 {
		return nil
	}
	if row == nil {
		row = &ipStatInternal{
			IP:           ip,
			VisitCount:   0,
			RecentEvents: []RecentEvent{},
			RecentPaths:  []RecentPath{},
		}
	}
	if row.Location == "" && lookup != nil {
		row.Location = lookup(ip)
	}
	for _, ev := range events {
		row.VisitCount++
		if ev.At.After(row.LastSeenAt) {
			row.LastSeenAt = ev.At
		}
		row.RecentEvents = append(row.RecentEvents, RecentEvent{At: ev.At, Path: ev.Path})
		row.RecentPaths = prependPath(row.RecentPaths, ev.Path, ev.At)
	}
	row.prune()
	return row.saveTx(tx)
}

func (s *Store) SetIPBlocked(ip string, blocked bool) error {
	val := 0
	if blocked {
		val = 1
	}
	now := time.Now().UTC().Format(time.RFC3339)

	var oldBlocked int
	err := s.db.QueryRow(`SELECT blocked FROM ip_stats WHERE ip = ?`, ip).Scan(&oldBlocked)
	existed := err != sql.ErrNoRows
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	res, err := s.db.Exec(`UPDATE ip_stats SET blocked = ?, updated_at = ? WHERE ip = ?`, val, now, ip)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()

	deltaIPs, deltaBlocked := 0, 0
	if n == 0 {
		_, err = s.db.Exec(`
INSERT INTO ip_stats (ip, visit_count, last_seen_at, freq_10min, recent_events, recent_paths, location, blocked, created_at, updated_at)
VALUES (?, 0, ?, 0, '[]', '[]', '', ?, ?, ?)`, ip, now, val, now, now)
		if err != nil {
			return err
		}
		deltaIPs = 1
		if blocked {
			deltaBlocked = 1
		}
	} else if existed {
		if oldBlocked == 0 && blocked {
			deltaBlocked = 1
		} else if oldBlocked == 1 && !blocked {
			deltaBlocked = -1
		}
	}
	return s.adjustGlobalStats(deltaIPs, 0, deltaBlocked)
}

func (s *Store) ListBlockedIPs() ([]string, error) {
	rows, err := s.db.Query(`SELECT ip FROM ip_stats WHERE blocked = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ips := make([]string, 0)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

type IPStatListItem struct {
	IP         string    `json:"ip"`
	Location   string    `json:"location"`
	VisitCount int       `json:"visit_count"`
	Freq10Min  int       `json:"freq_10min"`
	LastSeenAt time.Time `json:"last_seen_at"`
	TopPath    string    `json:"top_path"`
	Blocked    bool      `json:"blocked"`
}

func (s *Store) ListIPStats(f IPFilter) ([]IPStatListItem, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}

	where := "WHERE 1=1"
	args := []any{}
	if f.IP != "" {
		where += " AND ip LIKE ?"
		args = append(args, "%"+f.IP+"%")
	}
	if f.Blocked != nil {
		if *f.Blocked {
			where += " AND blocked = 1"
		} else {
			where += " AND blocked = 0"
		}
	}

	var total int
	if f.SkipTotal {
		total = -1
	} else {
		countArgs := append([]any{}, args...)
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ip_stats `+where, countArgs...).Scan(&total); err != nil {
			return nil, 0, err
		}
	}

	order := "visit_count DESC"
	switch f.Sort {
	case "last_seen":
		order = "last_seen_at DESC"
	case "freq_10min":
		order = "freq_10min DESC"
	}

	query := fmt.Sprintf(`
SELECT ip, visit_count, last_seen_at, freq_10min, location, blocked,
  COALESCE(json_extract(recent_paths, '$[0].path'), '')
FROM ip_stats %s ORDER BY %s LIMIT ? OFFSET ?`, where, order)
	args = append(args, f.Limit, f.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	list := make([]IPStatListItem, 0, f.Limit)
	for rows.Next() {
		var item IPStatListItem
		var lastSeen string
		var blocked int
		if err := rows.Scan(&item.IP, &item.VisitCount, &lastSeen, &item.Freq10Min, &item.Location, &blocked, &item.TopPath); err != nil {
			return nil, 0, err
		}
		item.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeen)
		item.Blocked = blocked == 1
		list = append(list, item)
	}
	return list, total, rows.Err()
}

func (s *Store) GetIPStat(ip string) (*IPStatRow, error) {
	row := s.db.QueryRow(`
SELECT ip, visit_count, last_seen_at, freq_10min, recent_events, recent_paths, location, blocked, created_at, updated_at
FROM ip_stats WHERE ip = ?`, ip)
	return scanIPStatRow(row)
}

func (s *Store) IPStatsSummary() (totalIPs, blockedIPs, totalVisits int, err error) {
	err = s.db.QueryRow(`
SELECT total_ips, blocked_ips, total_visits FROM global_stats WHERE id = 1`).
		Scan(&totalIPs, &blockedIPs, &totalVisits)
	return
}

func (s *Store) ensureGlobalStats() error {
	var cachedIPs int
	err := s.db.QueryRow(`SELECT total_ips FROM global_stats WHERE id = 1`).Scan(&cachedIPs)
	if err == sql.ErrNoRows {
		if _, e := s.db.Exec(`INSERT INTO global_stats (id, total_ips, total_visits, blocked_ips) VALUES (1, 0, 0, 0)`); e != nil {
			return e
		}
		return s.rebuildGlobalStats()
	}
	if err != nil {
		return err
	}
	if cachedIPs > 0 {
		return nil
	}
	var actual int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ip_stats`).Scan(&actual); err != nil {
		return err
	}
	if actual == 0 {
		return nil
	}
	return s.rebuildGlobalStats()
}

func (s *Store) rebuildGlobalStats() error {
	var totalIPs, blockedIPs, totalVisits int
	err := s.db.QueryRow(`
SELECT COUNT(*), COALESCE(SUM(visit_count), 0),
       COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0)
FROM ip_stats`).Scan(&totalIPs, &totalVisits, &blockedIPs)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
UPDATE global_stats SET total_ips = ?, total_visits = ?, blocked_ips = ? WHERE id = 1`,
		totalIPs, totalVisits, blockedIPs)
	return err
}

func (s *Store) adjustGlobalStats(deltaIPs, deltaVisits, deltaBlocked int) error {
	if deltaIPs == 0 && deltaVisits == 0 && deltaBlocked == 0 {
		return nil
	}
	_, err := s.db.Exec(`
UPDATE global_stats SET
  total_ips = total_ips + ?,
  total_visits = total_visits + ?,
  blocked_ips = blocked_ips + ?
WHERE id = 1`, deltaIPs, deltaVisits, deltaBlocked)
	return err
}

func (s *Store) adjustGlobalStatsTx(tx *sql.Tx, deltaIPs, deltaVisits, deltaBlocked int) error {
	if deltaIPs == 0 && deltaVisits == 0 && deltaBlocked == 0 {
		return nil
	}
	_, err := tx.Exec(`
UPDATE global_stats SET
  total_ips = total_ips + ?,
  total_visits = total_visits + ?,
  blocked_ips = blocked_ips + ?
WHERE id = 1`, deltaIPs, deltaVisits, deltaBlocked)
	return err
}

type ipStatInternal struct {
	IP           string
	VisitCount   int
	LastSeenAt   time.Time
	Freq10Min    int
	RecentEvents []RecentEvent
	RecentPaths  []RecentPath
	Location     string
	Blocked      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (r *ipStatInternal) prune() {
	cutoff := time.Now().UTC().Add(-freqWindow)
	events := r.RecentEvents[:0]
	for _, e := range r.RecentEvents {
		if e.At.After(cutoff) {
			events = append(events, e)
		}
	}
	r.RecentEvents = events
	r.Freq10Min = len(events)

	if len(r.RecentPaths) > maxRecentPaths {
		r.RecentPaths = r.RecentPaths[:maxRecentPaths]
	}
}

func prependPath(paths []RecentPath, path string, at time.Time) []RecentPath {
	out := []RecentPath{{Path: path, At: at}}
	for _, p := range paths {
		if p.Path == path {
			continue
		}
		out = append(out, p)
		if len(out) >= maxRecentPaths {
			break
		}
	}
	return out
}

func (r *ipStatInternal) saveTx(tx *sql.Tx) error {
	now := time.Now().UTC().Format(time.RFC3339)
	eventsJSON, _ := json.Marshal(r.RecentEvents)
	pathsJSON, _ := json.Marshal(r.RecentPaths)
	blocked := 0
	if r.Blocked {
		blocked = 1
	}

	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	created := r.CreatedAt.UTC().Format(time.RFC3339)

	_, err := tx.Exec(`
INSERT INTO ip_stats (ip, visit_count, last_seen_at, freq_10min, recent_events, recent_paths, location, blocked, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
  visit_count = excluded.visit_count,
  last_seen_at = excluded.last_seen_at,
  freq_10min = excluded.freq_10min,
  recent_events = excluded.recent_events,
  recent_paths = excluded.recent_paths,
  location = CASE WHEN excluded.location != '' THEN excluded.location ELSE ip_stats.location END,
  blocked = ip_stats.blocked,
  updated_at = excluded.updated_at
`, r.IP, r.VisitCount, r.LastSeenAt.UTC().Format(time.RFC3339), r.Freq10Min,
		string(eventsJSON), string(pathsJSON), r.Location, blocked, created, now)
	return err
}

func (s *Store) getIPStatRowTx(tx *sql.Tx, ip string) (*ipStatInternal, error) {
	m, err := s.loadIPStatsTx(tx, []string{ip})
	if err != nil {
		return nil, err
	}
	row, ok := m[ip]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) loadIPStatsTx(tx *sql.Tx, ips []string) (map[string]*ipStatInternal, error) {
	out := make(map[string]*ipStatInternal, len(ips))
	if len(ips) == 0 {
		return out, nil
	}
	const chunkSize = 400
	for i := 0; i < len(ips); i += chunkSize {
		end := i + chunkSize
		if end > len(ips) {
			end = len(ips)
		}
		chunk := ips[i:end]
		ph := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for j, ip := range chunk {
			ph[j] = "?"
			args[j] = ip
		}
		query := fmt.Sprintf(`
SELECT ip, visit_count, last_seen_at, freq_10min, recent_events, recent_paths, location, blocked, created_at, updated_at
FROM ip_stats WHERE ip IN (%s)`, strings.Join(ph, ","))
		rows, err := tx.Query(query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			row, err := scanIPStatInternal(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out[row.IP] = row
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanIPStatInternal(row scannable) (*ipStatInternal, error) {
	var r ipStatInternal
	var lastSeen, created, updated string
	var blocked int
	var eventsJSON, pathsJSON string
	if err := row.Scan(&r.IP, &r.VisitCount, &lastSeen, &r.Freq10Min, &eventsJSON, &pathsJSON, &r.Location, &blocked, &created, &updated); err != nil {
		return nil, err
	}
	r.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeen)
	r.CreatedAt, _ = time.Parse(time.RFC3339, created)
	r.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	r.Blocked = blocked == 1
	_ = json.Unmarshal([]byte(eventsJSON), &r.RecentEvents)
	_ = json.Unmarshal([]byte(pathsJSON), &r.RecentPaths)
	if r.RecentEvents == nil {
		r.RecentEvents = []RecentEvent{}
	}
	if r.RecentPaths == nil {
		r.RecentPaths = []RecentPath{}
	}
	return &r, nil
}

func scanIPStatRow(row scannable) (*IPStatRow, error) {
	internal, err := scanIPStatInternal(row)
	if err != nil {
		return nil, err
	}
	return &IPStatRow{
		IP:          internal.IP,
		Location:    internal.Location,
		VisitCount:  internal.VisitCount,
		LastSeenAt:  internal.LastSeenAt,
		Freq10Min:   internal.Freq10Min,
		RecentPaths: internal.RecentPaths,
		Blocked:     internal.Blocked,
		CreatedAt:   internal.CreatedAt,
		UpdatedAt:   internal.UpdatedAt,
	}, nil
}
