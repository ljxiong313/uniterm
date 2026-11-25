package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sync"

	"github.com/ys-ll/uniterm/backend/session"
)

const connectionsDBName = "connections.db"
const connectionsKeyName = "connections.db.key"

// storeFileName remains the legacy filename for one-shot migration helpers
// and sync compatibility. Local persistence uses connectionsDBName exclusively.
const storeFileName = "connections.json"

type PasswordStore interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}
type ConnectionStore struct {
	configDir     string
	passwordStore PasswordStore
	legacy        LegacyPasswordSource
	mu            sync.Mutex
	lastSavedHash string
	key           []byte
}

func NewConnectionStore(dir string) (*ConnectionStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	k, err := loadOrCreatePortableKey(filepath.Join(dir, connectionsKeyName))
	if err != nil {
		return nil, err
	}
	return &ConnectionStore{configDir: dir, key: k}, nil
}
func (s *ConnectionStore) SetPasswordStore(p PasswordStore)         { s.passwordStore = p }
func (s *ConnectionStore) SetLegacyKeychain(k LegacyPasswordSource) { s.legacy = k }
func (s *ConnectionStore) filePath() string                         { return filepath.Join(s.configDir, connectionsDBName) }
func (s *ConnectionStore) ensureKey() error {
	if len(s.key) == 32 {
		return nil
	}
	k, err := loadOrCreatePortableKey(filepath.Join(s.configDir, connectionsKeyName))
	if err != nil {
		return err
	}
	s.key = k
	return nil
}
func loadOrCreatePortableKey(path string) ([]byte, error) {
	if b, e := os.ReadFile(path); e == nil {
		if len(b) != 32 {
			return nil, errors.New("invalid database key length")
		}
		return b, nil
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	b := make([]byte, 32)
	if _, e := io.ReadFull(rand.Reader, b); e != nil {
		return nil, e
	}
	if e := os.WriteFile(path, b, 0600); e != nil {
		return nil, e
	}
	return b, nil
}
func (s *ConnectionStore) open() (*sql.DB, error) {
	db, e := sql.Open("sqlite", s.filePath())
	if e != nil {
		return nil, e
	}
	if _, e = db.Exec(`PRAGMA journal_mode=DELETE; CREATE TABLE IF NOT EXISTS connection_store (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, nonce BLOB NOT NULL, payload BLOB NOT NULL);`); e != nil {
		db.Close()
		return nil, e
	}
	return db, nil
}
func (s *ConnectionStore) Save(d session.ConnectionStoreData) error      { return s.save(d, false) }
func (s *ConnectionStore) ForceSave(d session.ConnectionStoreData) error { return s.save(d, true) }
func (s *ConnectionStore) save(d session.ConnectionStoreData, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureKey(); err != nil {
		return err
	}
	c := append([]session.ConnectionConfig(nil), d.Connections...)
	for i := range c {
		if e := session.ValidateTOTPConfig(c[i]); e != nil {
			return e
		}
		if c[i].AuthType == "identity" {
			c[i].Password = ""
		}
	}
	out := session.ConnectionStoreData{Groups: d.Groups, Connections: c}
	if !force {
		if h, e := jsonHash(out); e == nil && h == s.lastSavedHash {
			return nil
		}
	}
	if e := EncryptSecretFields("connections.json", &out, s.passwordStore); e != nil {
		return e
	}
	plain, e := json.Marshal(out)
	if e != nil {
		return e
	}
	n, ct, e := seal(s.key, plain)
	if e != nil {
		return e
	}
	db, e := s.open()
	if e != nil {
		return e
	}
	defer db.Close()
	_, e = db.Exec(`INSERT INTO connection_store(id,version,nonce,payload) VALUES(1,1,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,nonce=excluded.nonce,payload=excluded.payload`, n, ct)
	if e == nil {
		s.lastSavedHash, _ = jsonHash(d)
	}
	return e
}
func (s *ConnectionStore) Load() (session.ConnectionStoreData, error) {
	if err := s.ensureKey(); err != nil {
		return session.ConnectionStoreData{}, err
	}
	db, e := s.open()
	if e != nil {
		return session.ConnectionStoreData{}, e
	}
	defer db.Close()
	var n, ct []byte
	e = db.QueryRow(`SELECT nonce,payload FROM connection_store WHERE id=1`).Scan(&n, &ct)
	if errors.Is(e, sql.ErrNoRows) {
		return s.loadLegacyJSON()
	}
	if e != nil {
		return session.ConnectionStoreData{}, e
	}
	plain, e := openSeal(s.key, n, ct)
	if e != nil {
		return session.ConnectionStoreData{}, fmt.Errorf("decrypt connections database: %w", e)
	}
	var d session.ConnectionStoreData
	if e = json.Unmarshal(plain, &d); e != nil {
		return session.ConnectionStoreData{}, e
	}
	res, e := DecryptSecretFields("connections.json", &d, s.passwordStore)
	if e != nil {
		return session.ConnectionStoreData{}, e
	}
	if d.Groups == nil {
		d.Groups = []session.ConnectionGroup{}
	}
	if d.Connections == nil {
		d.Connections = []session.ConnectionConfig{}
	}
	if res.Plaintext > 0 { /* lazy re-encryption is deferred to the next explicit save */
	}
	s.lastSavedHash, _ = jsonHash(d)
	return d, nil
}
func (s *ConnectionStore) loadLegacyJSON() (session.ConnectionStoreData, error) {
	raw, e := os.ReadFile(filepath.Join(s.configDir, "connections.json"))
	if os.IsNotExist(e) {
		return session.ConnectionStoreData{Groups: []session.ConnectionGroup{}, Connections: []session.ConnectionConfig{}}, nil
	}
	if e != nil {
		return session.ConnectionStoreData{}, e
	}
	d, _, e := loadEncryptedData[session.ConnectionStoreData]("connections.json", raw, s.passwordStore)
	if e != nil || d.Groups == nil && d.Connections == nil {
		var c []session.ConnectionConfig
		c, _, e = loadEncryptedData[[]session.ConnectionConfig]("connections.json", raw, s.passwordStore)
		if e != nil {
			return session.ConnectionStoreData{}, e
		}
		d = session.ConnectionStoreData{Connections: c}
	}
	if d.Groups == nil {
		d.Groups = []session.ConnectionGroup{}
	}
	if d.Connections == nil {
		d.Connections = []session.ConnectionConfig{}
	}
	for i := range d.Connections {
		if d.Connections[i].AuthType == "password" && d.Connections[i].Password == "" && s.legacy != nil {
			if pw, x := s.legacy.GetPassword(d.Connections[i].ID); x == nil {
				d.Connections[i].Password = pw
			}
		}
	}
	if e = s.save(d, true); e != nil {
		return session.ConnectionStoreData{}, e
	}
	// The JSON file is a migration source only. Once the encrypted database is
	// durable, remove it so credentials are never maintained in two stores.
	_ = os.Remove(filepath.Join(s.configDir, "connections.json"))
	return d, nil
}
func (s *ConnectionStore) BlobName() string { return "connections.json" }
func (s *ConnectionStore) ExportPlain() ([]byte, error) {
	return exportPlainStore("connections.json", s.filePath(), s.Load)
}
func (s *ConnectionStore) ImportPlain(raw []byte) error { return importPlainStore(raw, s.Save) }
func seal(k, p []byte) ([]byte, []byte, error) {
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = io.ReadFull(rand.Reader, n); e != nil {
		return nil, nil, e
	}
	return n, g.Seal(nil, n, p, nil), nil
}
func openSeal(k, n, p []byte) ([]byte, error) {
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	return g.Open(nil, n, p, nil)
}
