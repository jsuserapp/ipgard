package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
	"ipgard/internal/db"
)

const passwordHashKey = "password_hash"

type Manager struct {
	store *db.Store
}

func New(store *db.Store) *Manager {
	return &Manager{store: store}
}

func (m *Manager) InitPassword(plain string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return m.store.SetSetting(passwordHashKey, string(hash))
}

func (m *Manager) EnsurePassword(plain string) error {
	existing, err := m.store.GetSetting(passwordHashKey)
	if err != nil {
		return err
	}
	if existing == "" {
		return m.InitPassword(plain)
	}
	return nil
}

func (m *Manager) ChangePassword(plain string) error {
	return m.InitPassword(plain)
}

func (m *Manager) Verify(plain string) error {
	hash, err := m.store.GetSetting(passwordHashKey)
	if err != nil {
		return err
	}
	if hash == "" {
		return errors.New("password not configured")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)); err != nil {
		return errors.New("invalid password")
	}
	return nil
}
