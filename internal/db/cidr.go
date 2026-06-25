package db

import (
	"database/sql"
	"time"
)

type CIDRBlock struct {
	CIDR      string    `json:"cidr"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) ListCIDRBlocks() ([]CIDRBlock, error) {
	rows, err := s.db.Query(`SELECT cidr, note, created_at FROM cidr_blocks ORDER BY cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]CIDRBlock, 0)
	for rows.Next() {
		var b CIDRBlock
		var created string
		if err := rows.Scan(&b.CIDR, &b.Note, &created); err != nil {
			return nil, err
		}
		b.CreatedAt, _ = time.Parse(time.RFC3339, created)
		list = append(list, b)
	}
	return list, rows.Err()
}

func (s *Store) ListCIDRStrings() ([]string, error) {
	rows, err := s.db.Query(`SELECT cidr FROM cidr_blocks ORDER BY cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []string
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return nil, err
		}
		list = append(list, cidr)
	}
	return list, rows.Err()
}

func (s *Store) AddCIDRBlock(cidr, note string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
INSERT INTO cidr_blocks (cidr, note, created_at) VALUES (?, ?, ?)
`, cidr, note, now)
	return err
}

func (s *Store) DeleteCIDRBlock(cidr string) error {
	res, err := s.db.Exec(`DELETE FROM cidr_blocks WHERE cidr = ?`, cidr)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) HasCIDRBlock(cidr string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM cidr_blocks WHERE cidr = ?`, cidr).Scan(&n)
	return n > 0, err
}
