package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// --- New types for Harbor-like features ---

type ImmutableTagRule struct {
	ID          int64     `json:"id"`
	Pattern     string    `json:"pattern"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

type APIToken struct {
	ID          int64      `json:"id"`
	UserID      int64      `json:"userId"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"tokenPrefix"`
	TokenHash   string     `json:"-"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

type RepoStats struct {
	Repo       string     `json:"repo"`
	PullCount  int64      `json:"pullCount"`
	PushCount  int64      `json:"pushCount"`
	LastPullAt *time.Time `json:"lastPullAt,omitempty"`
	LastPushAt *time.Time `json:"lastPushAt,omitempty"`
}

type Webhook struct {
	ID           int64     `json:"id"`
	URL          string    `json:"url"`
	SecretHeader string    `json:"secretHeader,omitempty"`
	Events       string    `json:"events"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"createdAt"`
}

func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

// VerifyPasswordHash checks if password matches the hash (supports bcrypt and legacy SHA256)
func VerifyPasswordHash(encoded, password string) bool {
	// Try bcrypt first
	if err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password)); err == nil {
		return true
	}
	// Fallback: legacy SHA256 format (sha256$salt$hash)
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "sha256" {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	hash := sha256.Sum256(append(salt, []byte(password)...))
	return subtle.ConstantTimeCompare(hash[:], expected) == 1
}

// NeedsPasswordUpgrade checks if a password hash uses the legacy SHA256 format
func NeedsPasswordUpgrade(encoded string) bool {
	return strings.HasPrefix(encoded, "sha256$")
}

// UpgradePassword re-hashes a password from legacy SHA256 to bcrypt
func UpgradePassword(encoded, password string) (string, error) {
	if !VerifyPasswordHash(encoded, password) {
		return "", errors.New("password does not match existing hash")
	}
	return HashPassword(password)
}

type Store struct {
	db    *sql.DB
	cache sync.Map // in-memory settings cache: key -> string value
}

// Default administrator seeded on first startup when the users table
// contains no enabled admin. The password is the literal default
// "change-me" — mustChangePassword=1 forces the operator to rotate it
// after the first login.
const (
	DefaultAdminUsername = "admin"
	DefaultAdminPassword = "change-me"
)

// Centralising defaults here lets the typed accessors return a sensible
// value when the key is missing, and lets the frontend rely on the API
// response (no separate default dictionary needed).
var DefaultSettings = map[string]string{
	// UI appearance / behavior
	"theme":       "light",
	"language":    "zh",
	"appLogo":     "RU",
	"appTitle":    "Registry UI",
	"appSubtitle": "",
	"pageSize":    "100",
	"showAudit":   "true",
	// TLS (managed via UI; cert/key stored in CERT_DIR, takes effect on restart)
	"tls_enabled": "false",
	// Retention
	"recycleGCDays": "30",
	// Global policy defaults (per-repo overrides live in the repositories table)
	"protection_mode":      "rules",
	"overwrite_action":     "recycle",
	"retention_keep_count": "0",
	"allow_anonymous_pull": "false",
	"push_create_repo":     "true",
}

type Namespace struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// Per-repo protection/overwrite codes stored in repositories table.
// -1 = unset (fall back to global setting / hardcoded default), >=0 = explicit value.
const (
	ProtectionModeUnset     = -1
	ProtectionModeRules     = 0
	ProtectionModeOverwrite = 1
	ProtectionModeImmutable = 2

	OverwriteActionUnset   = -1
	OverwriteActionRecycle = 0
	OverwriteActionKeep    = 1
)

type Repository struct {
	ID                 int64     `json:"id"`
	NamespaceID        int64     `json:"namespaceId"`
	Name               string    `json:"name"`
	AnonymousPull      bool      `json:"anonymousPull"`
	PushCreateRepo     int       `json:"pushCreateRepo"`     // -1=unset, 0=disabled, 1=enabled
	RetentionKeepCount int       `json:"retentionKeepCount"` // -1=unset, >=0=actual value
	ProtectionMode     int       `json:"protectionMode"`     // -1=unset, 0=rules, 1=overwrite, 2=immutable
	OverwriteAction    int       `json:"overwriteAction"`    // -1=unset, 0=recycle, 1=keep
	CreatedAt          time.Time `json:"createdAt"`
}

// ProtectionCodeToString maps a protection_mode integer code to its canonical
// string value. Defaults to "rules" for unknown codes.
func ProtectionCodeToString(code int) string {
	switch code {
	case ProtectionModeOverwrite:
		return "overwrite"
	case ProtectionModeImmutable:
		return "immutable"
	case ProtectionModeRules:
		return "rules"
	default:
		return "rules"
	}
}

// ProtectionStringToCode maps a string (from settings or API) to integer code.
// Empty/unknown values return Unset; the caller decides on a hardcoded default.
func ProtectionStringToCode(s string) int {
	switch s {
	case "overwrite":
		return ProtectionModeOverwrite
	case "immutable":
		return ProtectionModeImmutable
	case "rules":
		return ProtectionModeRules
	default:
		return ProtectionModeUnset
	}
}

// OverwriteCodeToString maps an overwrite_action integer code to its canonical
// string value. Defaults to "recycle" for unknown codes.
func OverwriteCodeToString(code int) string {
	switch code {
	case OverwriteActionKeep:
		return "keep"
	default:
		return "recycle"
	}
}

// OverwriteStringToCode maps a string (from settings or API) to integer code.
// Empty/unknown values return Unset.
func OverwriteStringToCode(s string) int {
	switch s {
	case "keep":
		return OverwriteActionKeep
	case "recycle":
		return OverwriteActionRecycle
	default:
		return OverwriteActionUnset
	}
}

type Image struct {
	ID           int64     `json:"id"`
	RepositoryID int64     `json:"repositoryId"`
	Tag          string    `json:"tag"`
	Digest       string    `json:"digest,omitempty"`
	ContentType  string    `json:"contentType,omitempty"`
	Size         int64     `json:"size,omitempty"`
	ArtifactType string    `json:"artifactType,omitempty"`
	Favorite     bool      `json:"favorite"`
	Note         string    `json:"note,omitempty"`
	Deleted      bool      `json:"deleted"`
	PushedAt     string    `json:"pushedAt,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type Recent struct {
	ID        int64     `json:"id"`
	Repo      string    `json:"repo"`
	Reference string    `json:"reference,omitempty"`
	Action    string    `json:"action"`
	VisitedAt time.Time `json:"visitedAt"`
}

type Audit struct {
	ID                int64     `json:"id"`
	UserID            int64     `json:"userId"`
	Username          string    `json:"username,omitempty"`
	Action            string    `json:"action"`
	Repo              string    `json:"repo,omitempty"`
	Reference         string    `json:"reference,omitempty"`
	Digest            string    `json:"digest,omitempty"`
	Status            string    `json:"status"`
	Detail            string    `json:"detail,omitempty"`
	ImageID           *int64    `json:"imageId,omitempty"`
	ImageNameSnapshot string    `json:"imageNameSnapshot,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
}

type RecycleItem struct {
	ID           int64     `json:"id"`
	Repo         string    `json:"repo"`
	Reference    string    `json:"reference"`
	Digest       string    `json:"digest"`
	ContentType  string    `json:"contentType"`
	ManifestBody []byte    `json:"-"`
	Status       string    `json:"status"`
	ImageID      *int64    `json:"imageId,omitempty"`
	Size         int64     `json:"size,omitempty"`
	DeletedAt    time.Time `json:"deletedAt"`
	RestoredAt   string    `json:"restoredAt,omitempty"`
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA synchronous=NORMAL`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS namespaces (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS repositories (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			namespace_id INTEGER NOT NULL REFERENCES namespaces(id),
			name TEXT NOT NULL,
			anonymous_pull INTEGER NOT NULL DEFAULT 0,
			push_create_repo INTEGER NOT NULL DEFAULT -1,
			retention_keep_count INTEGER NOT NULL DEFAULT -1,
			protection_mode INTEGER NOT NULL DEFAULT -1,
			overwrite_action INTEGER NOT NULL DEFAULT -1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(namespace_id, name)
		)`,
		`CREATE TABLE IF NOT EXISTS images (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repository_id INTEGER NOT NULL REFERENCES repositories(id),
			tag TEXT NOT NULL,
			digest TEXT NOT NULL DEFAULT '',
			content_type TEXT NOT NULL DEFAULT '',
			size INTEGER NOT NULL DEFAULT 0,
			artifact_type TEXT NOT NULL DEFAULT '',
			favorite INTEGER NOT NULL DEFAULT 0,
			note TEXT NOT NULL DEFAULT '',
			deleted INTEGER NOT NULL DEFAULT 0,
			pushed_at DATETIME DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_images_digest ON images(digest)`,
		`CREATE TABLE IF NOT EXISTS recent (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repo TEXT NOT NULL,
			reference TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL,
			visited_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			action TEXT NOT NULL,
			repo TEXT NOT NULL DEFAULT '',
			reference TEXT NOT NULL DEFAULT '',
			digest TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS recycle_bin (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repo TEXT NOT NULL,
			reference TEXT NOT NULL,
			digest TEXT NOT NULL,
			content_type TEXT NOT NULL DEFAULT '',
			manifest_body BLOB NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending_gc',
			size INTEGER NOT NULL DEFAULT 0,
			deleted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			restored_at DATETIME DEFAULT NULL,
			UNIQUE(repo, reference, digest)
		)`,
	}
	addStmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER NOT NULL DEFAULT 1,
			password_must_change INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS user_permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			namespace_pattern TEXT NOT NULL,
			can_read INTEGER NOT NULL DEFAULT 1,
			can_write INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, namespace_pattern)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_permissions_user_id ON user_permissions(user_id)`,
		`CREATE TABLE IF NOT EXISTS immutable_tag_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pattern TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS repo_descriptions (
			repo TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(repo)
		)`,
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			token_prefix TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			expires_at DATETIME DEFAULT NULL,
			last_used_at DATETIME DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix ON api_tokens(token_prefix)`,
		`CREATE TABLE IF NOT EXISTS repo_stats (
			repo TEXT NOT NULL,
			pull_count INTEGER NOT NULL DEFAULT 0,
			push_count INTEGER NOT NULL DEFAULT 0,
			last_pull_at DATETIME DEFAULT NULL,
			last_push_at DATETIME DEFAULT NULL,
			PRIMARY KEY(repo)
		)`,
		`CREATE TABLE IF NOT EXISTS webhooks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT NOT NULL,
			secret_header TEXT NOT NULL DEFAULT '',
			events TEXT NOT NULL DEFAULT 'push,delete,restore',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	// All DDL must run on the same connection so PRAGMA settings (notably
	// foreign_keys=ON) and ALTER TABLE statements share session state.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, stmt := range stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, stmt := range addStmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	// ALTER TABLE statements for schema upgrades (ignore errors if columns already exist)
	alterStmts := []string{
		`ALTER TABLE audit_logs ADD COLUMN image_id INTEGER REFERENCES images(id) ON DELETE SET NULL`,
		`ALTER TABLE audit_logs ADD COLUMN image_name_snapshot TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_logs ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE recycle_bin ADD COLUMN image_id INTEGER REFERENCES images(id) ON DELETE SET NULL`,
		`ALTER TABLE recycle_bin ADD COLUMN size INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE recent ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_recent_user_viewed ON recent(user_id, visited_at DESC)`,
		`DROP TABLE IF EXISTS favorites`,
		`ALTER TABLE images ADD COLUMN artifact_type TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE images ADD COLUMN size INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE repositories ADD COLUMN anonymous_pull INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE repositories ADD COLUMN push_create_repo INTEGER NOT NULL DEFAULT -1`,
		`ALTER TABLE repositories ADD COLUMN retention_keep_count INTEGER NOT NULL DEFAULT -1`,
		`ALTER TABLE repositories ADD COLUMN protection_mode INTEGER NOT NULL DEFAULT -1`,
		`ALTER TABLE repositories ADD COLUMN overwrite_action INTEGER NOT NULL DEFAULT -1`,
		`ALTER TABLE users ADD COLUMN password_must_change INTEGER NOT NULL DEFAULT 0`,
		`DROP INDEX IF EXISTS idx_images_repo_tag`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_images_repo_tag ON images(repository_id, tag)`,
		// Multi-registry removal: drop registries table and registry_id columns.
		`DROP TABLE IF EXISTS registries`,
		`DELETE FROM settings WHERE key='selectedRegistryId'`,
		`ALTER TABLE images DROP COLUMN registry_id`,
		`ALTER TABLE recent DROP COLUMN registry_id`,
		`ALTER TABLE audit_logs DROP COLUMN registry_id`,
		`ALTER TABLE recycle_bin DROP COLUMN registry_id`,
		`ALTER TABLE immutable_tag_rules DROP COLUMN registry_id`,
		`ALTER TABLE repo_descriptions DROP COLUMN registry_id`,
		`ALTER TABLE repo_stats DROP COLUMN registry_id`,
		`ALTER TABLE webhooks DROP COLUMN registry_id`,
	}
	for _, stmt := range alterStmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			if !isBenignMigrationError(err) {
				log.Printf("migration statement failed: %q: %v", stmt, err)
			}
		}
	}
	// Recycle bin, repo descriptions and repo stats have PRIMARY KEY or
	// UNIQUE constraints that include registry_id. SQLite can't DROP COLUMN
	// when it's part of such a constraint, so rebuild the tables in place
	// while preserving existing rows.
	if err := s.recycleAndRebuild(ctx, conn); err != nil {
		return err
	}
	// Verify the multi-registry columns were actually dropped.
	for _, t := range []string{"images", "recent", "audit_logs", "recycle_bin", "immutable_tag_rules", "repo_descriptions", "repo_stats", "webhooks"} {
		var n int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name='registry_id'`, t).Scan(&n); err == nil && n > 0 {
			log.Printf("WARN: registry_id still present in %s after migration", t)
		}
	}
	// Migrate allow_anonymous_pull from settings table to repositories.anonymous_pull
	if _, err := conn.ExecContext(ctx, `UPDATE repositories SET anonymous_pull = 1 WHERE anonymous_pull = 0 AND (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name IN (SELECT REPLACE(key, 'allow_anonymous_pull:', '') FROM settings WHERE key LIKE 'allow_anonymous_pull:%' AND value = 'true')`); err != nil {
		log.Printf("migration: transfer anonymous_pull from settings failed: %v", err)
	}
	// Migrate push_create_repo from settings table to repositories.push_create_repo
	if _, err := conn.ExecContext(ctx, `UPDATE repositories SET push_create_repo = CASE WHEN (SELECT value FROM settings WHERE key='push_create_repo:' || (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name) = 'true' THEN 1 ELSE 0 END WHERE push_create_repo = -1 AND (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name IN (SELECT REPLACE(key, 'push_create_repo:', '') FROM settings WHERE key LIKE 'push_create_repo:%')`); err != nil {
		log.Printf("migration: transfer push_create_repo from settings failed: %v", err)
	}
	// Migrate retention_keep_count from settings table to repositories.retention_keep_count
	if _, err := conn.ExecContext(ctx, `UPDATE repositories SET retention_keep_count = CAST((SELECT value FROM settings WHERE key='retention_keep_count:' || (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name) AS INTEGER) WHERE retention_keep_count = -1 AND (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name IN (SELECT REPLACE(key, 'retention_keep_count:', '') FROM settings WHERE key LIKE 'retention_keep_count:%')`); err != nil {
		log.Printf("migration: transfer retention_keep_count from settings failed: %v", err)
	}
	// Migrate protection_mode from settings table to repositories.protection_mode
	if _, err := conn.ExecContext(ctx, `UPDATE repositories SET protection_mode = CASE (SELECT value FROM settings WHERE key='protection_mode:' || (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name) WHEN 'overwrite' THEN 1 WHEN 'immutable' THEN 2 WHEN 'rules' THEN 0 ELSE -1 END WHERE protection_mode = -1 AND (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name IN (SELECT REPLACE(key, 'protection_mode:', '') FROM settings WHERE key LIKE 'protection_mode:%')`); err != nil {
		log.Printf("migration: transfer protection_mode from settings failed: %v", err)
	}
	// Fallback: legacy allow_overwrite:<repo> -> protection_mode = 1 (overwrite)
	if _, err := conn.ExecContext(ctx, `UPDATE repositories SET protection_mode = 1 WHERE protection_mode = -1 AND (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name IN (SELECT REPLACE(key, 'allow_overwrite:', '') FROM settings WHERE key LIKE 'allow_overwrite:%' AND value = 'true')`); err != nil {
		log.Printf("migration: transfer allow_overwrite to protection_mode failed: %v", err)
	}
	// Fallback: legacy immutable_repo:<repo> -> protection_mode = 2 (immutable)
	if _, err := conn.ExecContext(ctx, `UPDATE repositories SET protection_mode = 2 WHERE protection_mode = -1 AND (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name IN (SELECT REPLACE(key, 'immutable_repo:', '') FROM settings WHERE key LIKE 'immutable_repo:%' AND value = 'true')`); err != nil {
		log.Printf("migration: transfer immutable_repo to protection_mode failed: %v", err)
	}
	// Migrate overwrite_action from settings table to repositories.overwrite_action
	if _, err := conn.ExecContext(ctx, `UPDATE repositories SET overwrite_action = CASE (SELECT value FROM settings WHERE key='overwrite_action:' || (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name) WHEN 'keep' THEN 1 WHEN 'recycle' THEN 0 ELSE -1 END WHERE overwrite_action = -1 AND (SELECT n.name FROM namespaces n WHERE n.id=namespace_id) || '/' || name IN (SELECT REPLACE(key, 'overwrite_action:', '') FROM settings WHERE key LIKE 'overwrite_action:%')`); err != nil {
		log.Printf("migration: transfer overwrite_action from settings failed: %v", err)
	}
	// Cleanup: remove all per-repo legacy settings keys now that their data
	// lives in repositories table columns. Global default keys (no ':'
	// suffix) are preserved.
	if _, err := conn.ExecContext(ctx, `DELETE FROM settings WHERE key LIKE 'allow_anonymous_pull:%' OR key LIKE 'overwrite_action:%' OR key LIKE 'protection_mode:%' OR key LIKE 'push_create_repo:%' OR key LIKE 'retention_keep_count:%' OR key LIKE 'allow_overwrite:%' OR key LIKE 'immutable_repo:%'`); err != nil {
		log.Printf("migration: cleanup per-repo legacy settings failed: %v", err)
	}
	var regCount int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='registries'`).Scan(&regCount); err == nil && regCount > 0 {
		log.Printf("WARN: registries table still present after migration")
	}
	// Rebuild user_permissions and api_tokens to add REFERENCES users(id)
	// ON DELETE CASCADE plus the supporting indexes.
	if err := s.rebuildUserTables(ctx, conn); err != nil {
		return err
	}
	// Seed the default admin/change-me account on first startup when
	// the users table is empty of any enabled admin. Subsequent restarts
	// are no-ops. mustChangePassword=1 forces the operator to rotate
	// the default password after the first login.
	hasAdmin, herr := s.HasAdminUser(ctx)
	if herr != nil {
		log.Printf("migration: HasAdminUser check failed: %v", herr)
	} else if !hasAdmin {
		hash, err := HashPassword(DefaultAdminPassword)
		if err != nil {
			return fmt.Errorf("hash default admin password: %w", err)
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO users(username,password_hash,is_admin,enabled,password_must_change) VALUES(?,?,1,1,1) ON CONFLICT(username) DO NOTHING`, DefaultAdminUsername, hash)
		if err != nil {
			return fmt.Errorf("seed default admin: %w", err)
		}
		log.Printf("migration: seeded default admin user %q (must change password on first login)", DefaultAdminUsername)
	}
	// One-time cleanup of the legacy env-admin password hash that used
	// to live in the settings table.
	if _, err := conn.ExecContext(ctx, `DELETE FROM settings WHERE key='userPasswordHash'`); err != nil {
		log.Printf("migration: clear userPasswordHash setting failed: %v", err)
	}
	return nil
}

// recycleAndRebuild rebuilds the three tables whose PRIMARY KEY or UNIQUE
// constraint references registry_id. SQLite refuses DROP COLUMN on such
// columns, so the only safe migration is to copy rows into a new table
// that drops the registry_id column and PRIMARY KEY column.
func (s *Store) recycleAndRebuild(ctx context.Context, conn *sql.Conn) error {
	type rebuild struct {
		name      string
		hasColumn bool
		newSchema string
		copySQL   string
	}
	for _, r := range []rebuild{
		{
			name:      "recycle_bin",
			hasColumn: true,
			newSchema: `CREATE TABLE recycle_bin_new (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				repo TEXT NOT NULL,
				reference TEXT NOT NULL,
				digest TEXT NOT NULL,
				content_type TEXT NOT NULL DEFAULT '',
				manifest_body BLOB NOT NULL,
				status TEXT NOT NULL DEFAULT 'pending_gc',
				image_id INTEGER REFERENCES images(id) ON DELETE SET NULL,
				size INTEGER NOT NULL DEFAULT 0,
				deleted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				restored_at DATETIME DEFAULT NULL,
				UNIQUE(repo, reference, digest)
			)`,
			copySQL: `INSERT INTO recycle_bin_new(id,repo,reference,digest,content_type,manifest_body,status,image_id,deleted_at,restored_at) SELECT id,repo,reference,digest,content_type,manifest_body,status,image_id,deleted_at,restored_at FROM recycle_bin`,
		},
		{
			name:      "repo_descriptions",
			hasColumn: true,
			newSchema: `CREATE TABLE repo_descriptions_new (
				repo TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY(repo)
			)`,
			copySQL: `INSERT INTO repo_descriptions_new(repo,description,updated_at) SELECT repo,description,updated_at FROM repo_descriptions`,
		},
		{
			name:      "repo_stats",
			hasColumn: true,
			newSchema: `CREATE TABLE repo_stats_new (
				repo TEXT NOT NULL,
				pull_count INTEGER NOT NULL DEFAULT 0,
				push_count INTEGER NOT NULL DEFAULT 0,
				last_pull_at DATETIME DEFAULT NULL,
				last_push_at DATETIME DEFAULT NULL,
				PRIMARY KEY(repo)
			)`,
			copySQL: `INSERT INTO repo_stats_new(repo,pull_count,push_count,last_pull_at,last_push_at) SELECT repo,pull_count,push_count,last_pull_at,last_push_at FROM repo_stats`,
		},
	} {
		// Check if the table still has a registry_id column by inspecting
		// the column list in its CREATE TABLE statement. The pragma_table_info
		// table-valued function is not reliably available in modernc.org/sqlite.
		var cols string
		if err := conn.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, r.name).Scan(&cols); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return err
		}
		if !strings.Contains(cols, "registry_id") {
			continue
		}
		log.Printf("rebuilding %s to drop registry_id column", r.name)
		// Clean up any leftover _new table from a previous failed attempt.
		if _, err := conn.ExecContext(ctx, `DROP TABLE IF EXISTS `+r.name+`_new`); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, r.newSchema); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, r.copySQL); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `DROP TABLE `+r.name); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `ALTER TABLE `+r.name+`_new RENAME TO `+r.name); err != nil {
			return err
		}
	}
	return nil
}

// rebuildUserTables rebuilds user_permissions and api_tokens to add the
// REFERENCES users(id) ON DELETE CASCADE foreign key constraint and
// per-user / per-prefix indexes. SQLite cannot ALTER TABLE ADD FOREIGN
// KEY, so we copy the rows into a new table and rename.
//
// The migration is detected by checking whether the live CREATE TABLE
// SQL contains the foreign-key declaration; if it already does, the
// table is left untouched (idempotent).
func (s *Store) rebuildUserTables(ctx context.Context, conn *sql.Conn) error {
	type rebuild struct {
		name      string
		newSchema string
		copySQL   string
		fkMarker  string
	}
	for _, r := range []rebuild{
		{
			name: "user_permissions",
			newSchema: `CREATE TABLE user_permissions_new (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				namespace_pattern TEXT NOT NULL,
				can_read INTEGER NOT NULL DEFAULT 1,
				can_write INTEGER NOT NULL DEFAULT 0,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				UNIQUE(user_id, namespace_pattern)
			)`,
			copySQL:  `INSERT INTO user_permissions_new(user_id,namespace_pattern,can_read,can_write,created_at) SELECT user_id,namespace_pattern,MAX(can_read),MAX(can_write),MIN(created_at) FROM user_permissions WHERE user_id IN (SELECT id FROM users) GROUP BY user_id,namespace_pattern`,
			fkMarker: `UNIQUE(user_id, namespace_pattern)`,
		},
		{
			name: "api_tokens",
			newSchema: `CREATE TABLE api_tokens_new (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				name TEXT NOT NULL,
				token_hash TEXT NOT NULL,
				token_prefix TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				expires_at DATETIME DEFAULT NULL,
				last_used_at DATETIME DEFAULT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
			)`,
			copySQL:  `INSERT INTO api_tokens_new(id,user_id,name,token_hash,token_prefix,description,expires_at,last_used_at,created_at) SELECT id,user_id,name,token_hash,token_prefix,description,expires_at,last_used_at,created_at FROM api_tokens WHERE user_id IN (SELECT id FROM users)`,
			fkMarker: `REFERENCES users(id) ON DELETE CASCADE`,
		},
	} {
		var ddl string
		if err := conn.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, r.name).Scan(&ddl); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return err
		}
		if strings.Contains(ddl, r.fkMarker) {
			continue // already rebuilt
		}
		log.Printf("rebuilding %s to add REFERENCES users(id) ON DELETE CASCADE", r.name)
		if _, err := conn.ExecContext(ctx, `DROP TABLE IF EXISTS `+r.name+`_new`); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, r.newSchema); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, r.copySQL); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `DROP TABLE `+r.name); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `ALTER TABLE `+r.name+`_new RENAME TO `+r.name); err != nil {
			return err
		}
		// Re-create the supporting indexes on the renamed table.
		switch r.name {
		case "user_permissions":
			if _, err := conn.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_user_permissions_user_id ON user_permissions(user_id)`); err != nil {
				return err
			}
		case "api_tokens":
			if _, err := conn.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id)`); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix ON api_tokens(token_prefix)`); err != nil {
				return err
			}
		}
	}
	return nil
}

// isBenignMigrationError reports whether an error from the migration loop
// can be ignored. The legacy ADD COLUMN statements raise "duplicate column"
// when the column already exists; DROP TABLE / DROP COLUMN on missing
// objects raise errors that are also safe to ignore.
func isBenignMigrationError(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "duplicate column name"),
		strings.Contains(msg, "no such column"),
		strings.Contains(msg, "no such table"),
		strings.Contains(msg, "already exists"):
		return true
	}
	return false
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	// Empty value is treated as "delete the key" so callers can use a single
	// call to clear a setting (e.g. legacy per-repo overrides after the
	// data has been moved into the repositories table).
	if value == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key=?`, key)
		if err != nil {
			return err
		}
		s.cache.Delete(key)
		return nil
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	if err != nil {
		return err
	}
	s.cache.Store(key, value)
	return nil
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	if v, ok := s.cache.Load(key); ok {
		vv, _ := v.(string)
		return vv, nil
	}
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		s.cache.Store(key, "") // remember "absent" to avoid repeated lookups
		return "", nil
	}
	if err != nil {
		return "", err
	}
	s.cache.Store(key, v)
	return v, nil
}

// GetSettingInt returns the integer value for key, or def when the key is
// absent, empty, or does not parse as a base-10 integer. Non-numeric input
// does NOT silently coerce to 0 anymore (the previous _=Atoi pattern would
// silently disable GC when the user typed "abc").
func (s *Store) GetSettingInt(ctx context.Context, key string, def int) int {
	v, _ := s.GetSetting(ctx, key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// GetSettingBool returns the boolean value for key, or def when the key is
// absent. Recognised truthy values: "true", "1", "yes", "on". Recognised
// falsy values: "false", "0", "no", "off". Anything else falls back to def.
func (s *Store) GetSettingBool(ctx context.Context, key string, def bool) bool {
	v, _ := s.GetSetting(ctx, key)
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return def
	}
}

func (s *Store) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key,value FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Re-seed the cache from the authoritative DB result so that values
	// that were written by another process / a different Store instance
	// are reflected on the next GetSetting call.
	for k, v := range out {
		s.cache.Store(k, v)
	}
	return out, nil
}

func (s *Store) UpsertNamespace(ctx context.Context, name string) (Namespace, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO namespaces(name) VALUES(?) ON CONFLICT(name) DO NOTHING`, name)
	if err != nil {
		return Namespace{}, err
	}
	var ns Namespace
	err = s.db.QueryRowContext(ctx, `SELECT id,name,created_at FROM namespaces WHERE name=?`, name).Scan(&ns.ID, &ns.Name, &ns.CreatedAt)
	return ns, err
}

func (s *Store) ListNamespaces(ctx context.Context) ([]Namespace, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,created_at FROM namespaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Namespace
	for rows.Next() {
		var ns Namespace
		if err := rows.Scan(&ns.ID, &ns.Name, &ns.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, ns)
	}
	return out, rows.Err()
}

func (s *Store) GetNamespace(ctx context.Context, name string) (Namespace, error) {
	var ns Namespace
	err := s.db.QueryRowContext(ctx, `SELECT id,name,created_at FROM namespaces WHERE name=?`, name).Scan(&ns.ID, &ns.Name, &ns.CreatedAt)
	return ns, err
}

func (s *Store) GetNamespaceByID(ctx context.Context, id int64) (Namespace, error) {
	var ns Namespace
	err := s.db.QueryRowContext(ctx, `SELECT id,name,created_at FROM namespaces WHERE id=?`, id).Scan(&ns.ID, &ns.Name, &ns.CreatedAt)
	return ns, err
}

func (s *Store) DeleteNamespace(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM namespaces WHERE id=?`, id)
	return err
}

// SetRepositoryAnonymousPull sets the anonymous_pull flag for a repository
// identified by its namespaced name (e.g. "library/nginx").
func (s *Store) SetRepositoryAnonymousPull(ctx context.Context, nsName, repoName string, allowed bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE repositories SET anonymous_pull=? WHERE namespace_id=(SELECT id FROM namespaces WHERE name=?) AND name=?`, boolInt(allowed), nsName, repoName)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("repository not found: %s/%s", nsName, repoName)
	}
	return nil
}

// IsRepoAnonymousPullAllowed checks the per-repo anonymous_pull flag.
func (s *Store) IsRepoAnonymousPullAllowed(ctx context.Context, nsName, repoName string) (bool, error) {
	var anon int
	err := s.db.QueryRowContext(ctx, `SELECT anonymous_pull FROM repositories r JOIN namespaces n ON n.id=r.namespace_id WHERE n.name=? AND r.name=?`, nsName, repoName).Scan(&anon)
	if err != nil {
		return false, err
	}
	return anon != 0, nil
}

// SetRepositoryPushCreate sets the push_create_repo flag for a repository.
// value: -1=unset(use global), 0=disabled, 1=enabled
func (s *Store) SetRepositoryPushCreate(ctx context.Context, nsName, repoName string, value int) error {
	res, err := s.db.ExecContext(ctx, `UPDATE repositories SET push_create_repo=? WHERE namespace_id=(SELECT id FROM namespaces WHERE name=?) AND name=?`, value, nsName, repoName)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("repository not found: %s/%s", nsName, repoName)
	}
	return nil
}

// GetRepoPushCreate returns the per-repo push_create_repo value.
// Returns -1 if not set (use global default).
func (s *Store) GetRepoPushCreate(ctx context.Context, nsName, repoName string) (int, error) {
	var val int
	err := s.db.QueryRowContext(ctx, `SELECT push_create_repo FROM repositories r JOIN namespaces n ON n.id=r.namespace_id WHERE n.name=? AND r.name=?`, nsName, repoName).Scan(&val)
	if err != nil {
		return -1, err
	}
	return val, nil
}

// SetRepositoryRetentionKeepCount sets the retention_keep_count for a repository.
// value: -1=unset(use global), >=0=actual keep count
func (s *Store) SetRepositoryRetentionKeepCount(ctx context.Context, nsName, repoName string, value int) error {
	res, err := s.db.ExecContext(ctx, `UPDATE repositories SET retention_keep_count=? WHERE namespace_id=(SELECT id FROM namespaces WHERE name=?) AND name=?`, value, nsName, repoName)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("repository not found: %s/%s", nsName, repoName)
	}
	return nil
}

// GetRepoRetentionKeepCount returns the per-repo retention_keep_count value.
// Returns -1 if not set (use global default).
func (s *Store) GetRepoRetentionKeepCount(ctx context.Context, nsName, repoName string) (int, error) {
	var val int
	err := s.db.QueryRowContext(ctx, `SELECT retention_keep_count FROM repositories r JOIN namespaces n ON n.id=r.namespace_id WHERE n.name=? AND r.name=?`, nsName, repoName).Scan(&val)
	if err != nil {
		return -1, err
	}
	return val, nil
}

// SetRepositoryProtectionMode sets the per-repo protection_mode code.
// code: -1=unset(use global), 0=rules, 1=overwrite, 2=immutable.
func (s *Store) SetRepositoryProtectionMode(ctx context.Context, nsName, repoName string, code int) error {
	res, err := s.db.ExecContext(ctx, `UPDATE repositories SET protection_mode=? WHERE namespace_id=(SELECT id FROM namespaces WHERE name=?) AND name=?`, code, nsName, repoName)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("repository not found: %s/%s", nsName, repoName)
	}
	return nil
}

// GetRepoProtectionMode returns the per-repo protection_mode code, or -1 if unset.
func (s *Store) GetRepoProtectionMode(ctx context.Context, nsName, repoName string) (int, error) {
	var val int
	err := s.db.QueryRowContext(ctx, `SELECT protection_mode FROM repositories r JOIN namespaces n ON n.id=r.namespace_id WHERE n.name=? AND r.name=?`, nsName, repoName).Scan(&val)
	if err != nil {
		return -1, err
	}
	return val, nil
}

// SetRepositoryOverwriteAction sets the per-repo overwrite_action code.
// code: -1=unset(use global), 0=recycle, 1=keep.
func (s *Store) SetRepositoryOverwriteAction(ctx context.Context, nsName, repoName string, code int) error {
	res, err := s.db.ExecContext(ctx, `UPDATE repositories SET overwrite_action=? WHERE namespace_id=(SELECT id FROM namespaces WHERE name=?) AND name=?`, code, nsName, repoName)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("repository not found: %s/%s", nsName, repoName)
	}
	return nil
}

// GetRepoOverwriteAction returns the per-repo overwrite_action code, or -1 if unset.
func (s *Store) GetRepoOverwriteAction(ctx context.Context, nsName, repoName string) (int, error) {
	var val int
	err := s.db.QueryRowContext(ctx, `SELECT overwrite_action FROM repositories r JOIN namespaces n ON n.id=r.namespace_id WHERE n.name=? AND r.name=?`, nsName, repoName).Scan(&val)
	if err != nil {
		return -1, err
	}
	return val, nil
}

func (s *Store) UpsertRepository(ctx context.Context, namespaceID int64, name string) (Repository, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO repositories(namespace_id,name) VALUES(?,?) ON CONFLICT(namespace_id,name) DO NOTHING`, namespaceID, name)
	if err != nil {
		return Repository{}, err
	}
	return s.GetRepositoryByNamespaceAndName(ctx, namespaceID, name)
}

func (s *Store) GetRepositoryByNamespaceAndName(ctx context.Context, namespaceID int64, name string) (Repository, error) {
	var repo Repository
	var anon int
	err := s.db.QueryRowContext(ctx, `SELECT id,namespace_id,name,anonymous_pull,push_create_repo,retention_keep_count,protection_mode,overwrite_action,created_at FROM repositories WHERE namespace_id=? AND name=?`, namespaceID, name).Scan(&repo.ID, &repo.NamespaceID, &repo.Name, &anon, &repo.PushCreateRepo, &repo.RetentionKeepCount, &repo.ProtectionMode, &repo.OverwriteAction, &repo.CreatedAt)
	if err != nil {
		return repo, err
	}
	repo.AnonymousPull = anon != 0
	return repo, nil
}

func (s *Store) GetRepositoryByID(ctx context.Context, id int64) (Repository, error) {
	var repo Repository
	var anon int
	err := s.db.QueryRowContext(ctx, `SELECT id,namespace_id,name,anonymous_pull,push_create_repo,retention_keep_count,protection_mode,overwrite_action,created_at FROM repositories WHERE id=?`, id).Scan(&repo.ID, &repo.NamespaceID, &repo.Name, &anon, &repo.PushCreateRepo, &repo.RetentionKeepCount, &repo.ProtectionMode, &repo.OverwriteAction, &repo.CreatedAt)
	if err != nil {
		return repo, err
	}
	repo.AnonymousPull = anon != 0
	return repo, nil
}

func (s *Store) GetRepositoryByNamespacedName(ctx context.Context, nsName, repoName string) (Repository, error) {
	var repo Repository
	var anon int
	err := s.db.QueryRowContext(ctx, `SELECT r.id,r.namespace_id,r.name,r.anonymous_pull,r.push_create_repo,r.retention_keep_count,r.protection_mode,r.overwrite_action,r.created_at FROM repositories r JOIN namespaces n ON n.id=r.namespace_id WHERE n.name=? AND r.name=?`, nsName, repoName).Scan(&repo.ID, &repo.NamespaceID, &repo.Name, &anon, &repo.PushCreateRepo, &repo.RetentionKeepCount, &repo.ProtectionMode, &repo.OverwriteAction, &repo.CreatedAt)
	if err != nil {
		return repo, err
	}
	repo.AnonymousPull = anon != 0
	return repo, nil
}

func (s *Store) ListAllRepoNames(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT n.name || '/' || r.name FROM repositories r JOIN namespaces n ON n.id=r.namespace_id ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func (s *Store) UpsertImage(ctx context.Context, img Image) (Image, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO images(repository_id,tag,digest,content_type,size,artifact_type,favorite,note,deleted,pushed_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(repository_id,tag) DO UPDATE SET digest=excluded.digest,content_type=excluded.content_type,size=excluded.size,artifact_type=excluded.artifact_type,favorite=excluded.favorite,note=excluded.note,deleted=excluded.deleted,pushed_at=excluded.pushed_at,updated_at=CURRENT_TIMESTAMP`, img.RepositoryID, img.Tag, img.Digest, img.ContentType, img.Size, img.ArtifactType, boolInt(img.Favorite), img.Note, boolInt(img.Deleted), img.PushedAt)
	return img, err
}

func (s *Store) SyncImage(ctx context.Context, img Image) (Image, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO images(repository_id,tag,digest,content_type,size,artifact_type,favorite,note,deleted,pushed_at) VALUES(?,?,?,?,?,?,0,'',0,?) ON CONFLICT(repository_id,tag) DO UPDATE SET digest=excluded.digest,content_type=excluded.content_type,size=excluded.size,artifact_type=excluded.artifact_type,deleted=0,pushed_at=excluded.pushed_at,updated_at=CURRENT_TIMESTAMP`, img.RepositoryID, img.Tag, img.Digest, img.ContentType, img.Size, img.ArtifactType, img.PushedAt)
	return img, err
}

func (s *Store) GetImageByDigest(ctx context.Context, digest string) (*Image, error) {
	var img Image
	var deleted, favorite int
	var pushedAt sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id,repository_id,tag,digest,content_type,size,artifact_type,favorite,note,deleted,pushed_at,created_at,updated_at FROM images WHERE digest=? ORDER BY id LIMIT 1`, digest).Scan(&img.ID, &img.RepositoryID, &img.Tag, &img.Digest, &img.ContentType, &img.Size, &img.ArtifactType, &favorite, &img.Note, &deleted, &pushedAt, &img.CreatedAt, &img.UpdatedAt)
	if err != nil {
		return nil, err
	}
	img.Favorite = favorite != 0
	img.Deleted = deleted != 0
	if pushedAt.Valid {
		img.PushedAt = pushedAt.String
	}
	return &img, nil
}

// ListTagsByDigest returns the non-deleted tags in a repository that share
// the given digest, excluding excludeTag if non-empty.
func (s *Store) ListTagsByDigest(ctx context.Context, repositoryID int64, digest, excludeTag string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tag FROM images WHERE repository_id=? AND digest=? AND deleted=0 AND tag != ? ORDER BY tag`, repositoryID, digest, excludeTag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, err
		}
		out = append(out, tag)
	}
	return out, rows.Err()
}

func (s *Store) GetImageByRepoTag(ctx context.Context, repositoryID int64, tag string) (Image, error) {
	var img Image
	var deleted, favorite int
	var pushedAt sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id,repository_id,tag,digest,content_type,size,artifact_type,favorite,note,deleted,pushed_at,created_at,updated_at FROM images WHERE repository_id=? AND tag=?`, repositoryID, tag).Scan(&img.ID, &img.RepositoryID, &img.Tag, &img.Digest, &img.ContentType, &img.Size, &img.ArtifactType, &favorite, &img.Note, &deleted, &pushedAt, &img.CreatedAt, &img.UpdatedAt)
	if err != nil {
		return Image{}, err
	}
	img.Favorite = favorite != 0
	img.Deleted = deleted != 0
	if pushedAt.Valid {
		img.PushedAt = pushedAt.String
	}
	return img, nil
}

func (s *Store) ListImages(ctx context.Context, onlyFavorites bool, includeDeleted bool) ([]Image, error) {
	where := `1=1`
	var args []any
	if onlyFavorites {
		where += ` AND favorite=1`
	}
	if !includeDeleted {
		where += ` AND deleted=0`
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,repository_id,tag,digest,content_type,size,artifact_type,favorite,note,deleted,pushed_at,created_at,updated_at FROM images WHERE `+where+` ORDER BY updated_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Image
	for rows.Next() {
		var img Image
		var deleted, favorite int
		var pushedAt sql.NullString
		if err := rows.Scan(&img.ID, &img.RepositoryID, &img.Tag, &img.Digest, &img.ContentType, &img.Size, &img.ArtifactType, &favorite, &img.Note, &deleted, &pushedAt, &img.CreatedAt, &img.UpdatedAt); err != nil {
			return nil, err
		}
		img.Favorite = favorite != 0
		img.Deleted = deleted != 0
		if pushedAt.Valid {
			img.PushedAt = pushedAt.String
		}
		out = append(out, img)
	}
	return out, rows.Err()
}

func (s *Store) ListImagesByRepo(ctx context.Context, repositoryID int64) ([]Image, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,repository_id,tag,digest,content_type,size,artifact_type,favorite,note,deleted,pushed_at,created_at,updated_at FROM images WHERE repository_id=? AND deleted=0 ORDER BY created_at DESC, id DESC`, repositoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Image
	for rows.Next() {
		var img Image
		var deleted, favorite int
		var pushedAt sql.NullString
		if err := rows.Scan(&img.ID, &img.RepositoryID, &img.Tag, &img.Digest, &img.ContentType, &img.Size, &img.ArtifactType, &favorite, &img.Note, &deleted, &pushedAt, &img.CreatedAt, &img.UpdatedAt); err != nil {
			return nil, err
		}
		img.Favorite = favorite != 0
		img.Deleted = deleted != 0
		if pushedAt.Valid {
			img.PushedAt = pushedAt.String
		}
		out = append(out, img)
	}
	return out, rows.Err()
}

func (s *Store) SetImageFavorite(ctx context.Context, repositoryID int64, tag string, favorite bool, note string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE images SET favorite=?, note=?, updated_at=CURRENT_TIMESTAMP WHERE repository_id=? AND tag=?`, boolInt(favorite), note, repositoryID, tag)
	return err
}

func (s *Store) SoftDeleteImage(ctx context.Context, repositoryID int64, tag string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE images SET deleted=1, updated_at=CURRENT_TIMESTAMP WHERE repository_id=? AND tag=?`, repositoryID, tag)
	return err
}

func (s *Store) SoftDeleteImageByDigest(ctx context.Context, repositoryID int64, digest string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE images SET deleted=1, updated_at=CURRENT_TIMESTAMP WHERE repository_id=? AND digest=?`, repositoryID, digest)
	return err
}

func (s *Store) GetImageByID(ctx context.Context, id int64) (*Image, error) {
	var img Image
	var deleted, favorite int
	var pushedAt sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id,repository_id,tag,digest,content_type,size,artifact_type,favorite,note,deleted,pushed_at,created_at,updated_at FROM images WHERE id=?`, id).Scan(&img.ID, &img.RepositoryID, &img.Tag, &img.Digest, &img.ContentType, &img.Size, &img.ArtifactType, &favorite, &img.Note, &deleted, &pushedAt, &img.CreatedAt, &img.UpdatedAt)
	if err != nil {
		return nil, err
	}
	img.Favorite = favorite != 0
	img.Deleted = deleted != 0
	if pushedAt.Valid {
		img.PushedAt = pushedAt.String
	}
	return &img, nil
}

func (s *Store) AddRecent(ctx context.Context, userID int64, repo, ref, action string) error {
	// 1. Dedupe by (user_id, repo): remove any existing rows for the same
	//    repo so the same repo only appears once in the user's history.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM recent WHERE user_id=? AND repo=?`, userID, repo); err != nil {
		return err
	}
	// 2. Insert the new visit row.
	if _, err := s.db.ExecContext(ctx, `INSERT INTO recent(user_id,repo,reference,action) VALUES(?,?,?,?)`, userID, repo, ref, action); err != nil {
		return err
	}
	// 3. Trim: keep at most 100 most-recent rows per user.
	_, err := s.db.ExecContext(ctx, `DELETE FROM recent WHERE user_id=? AND id NOT IN (SELECT id FROM recent WHERE user_id=? ORDER BY visited_at DESC, id DESC LIMIT 100)`, userID, userID)
	return err
}

func (s *Store) ListRecent(ctx context.Context, userID int64, limit int) ([]Recent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,repo,reference,action,visited_at FROM recent WHERE user_id=? ORDER BY visited_at DESC,id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Recent
	for rows.Next() {
		var r Recent
		if err := rows.Scan(&r.ID, &r.Repo, &r.Reference, &r.Action, &r.VisitedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddAudit(ctx context.Context, userID int64, action, repo, ref, digest, status, detail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_logs(user_id,action,repo,reference,digest,status,detail) VALUES(?,?,?,?,?,?,?)`, userID, action, repo, ref, digest, status, detail)
	return err
}

func (s *Store) AddAuditWithImage(ctx context.Context, userID int64, action, repo, ref, digest, status, detail string, imageID *int64, imageNameSnapshot string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_logs(user_id,action,repo,reference,digest,status,detail,image_id,image_name_snapshot) VALUES(?,?,?,?,?,?,?,?,?)`, userID, action, repo, ref, digest, status, detail, imageID, imageNameSnapshot)
	return err
}

func (s *Store) ListAudit(ctx context.Context, userID int64, limit int) ([]Audit, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args := []any{}
	where := "1=1"
	if userID > 0 {
		where += " AND a.user_id=?"
		args = append(args, userID)
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.user_id,COALESCE(u.username,''),a.action,a.repo,a.reference,a.digest,a.status,a.detail,a.image_id,a.image_name_snapshot,a.created_at FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id WHERE `+where+` ORDER BY a.created_at DESC,a.id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Audit
	for rows.Next() {
		var a Audit
		var imageID sql.NullInt64
		if err := rows.Scan(&a.ID, &a.UserID, &a.Username, &a.Action, &a.Repo, &a.Reference, &a.Digest, &a.Status, &a.Detail, &imageID, &a.ImageNameSnapshot, &a.CreatedAt); err != nil {
			return nil, err
		}
		if imageID.Valid {
			a.ImageID = &imageID.Int64
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) AddRecycleItem(ctx context.Context, item RecycleItem) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO recycle_bin(repo,reference,digest,content_type,manifest_body,size,status,image_id) VALUES(?,?,?,?,?,?,'pending_gc',?) ON CONFLICT(repo,reference,digest) DO UPDATE SET content_type=excluded.content_type,manifest_body=excluded.manifest_body,size=excluded.size,status='pending_gc',deleted_at=CASE WHEN recycle_bin.status='restored' THEN CURRENT_TIMESTAMP ELSE recycle_bin.deleted_at END,restored_at=NULL,image_id=excluded.image_id`, item.Repo, item.Reference, item.Digest, item.ContentType, item.ManifestBody, item.Size, item.ImageID)
	return err
}

func (s *Store) DeletePendingGCByRepoRef(ctx context.Context, repo, ref string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM recycle_bin WHERE status='pending_gc' AND repo=? AND reference=?`, repo, ref)
	return err
}

func (s *Store) ListRecycleItems(ctx context.Context, includeRestored bool, limit int) ([]RecycleItem, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	where := `1=1`
	if !includeRestored {
		where += ` AND status='pending_gc'`
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,repo,reference,digest,content_type,status,image_id,deleted_at,COALESCE(restored_at,'') FROM recycle_bin WHERE `+where+` ORDER BY deleted_at DESC,id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RecycleItem
	for rows.Next() {
		var item RecycleItem
		var imageID sql.NullInt64
		if err := rows.Scan(&item.ID, &item.Repo, &item.Reference, &item.Digest, &item.ContentType, &item.Status, &imageID, &item.DeletedAt, &item.RestoredAt); err != nil {
			return nil, err
		}
		if imageID.Valid {
			item.ImageID = &imageID.Int64
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetRecycleItem(ctx context.Context, id int64) (RecycleItem, error) {
	var item RecycleItem
	var imageID sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id,repo,reference,digest,content_type,manifest_body,status,image_id,deleted_at,COALESCE(restored_at,'') FROM recycle_bin WHERE id=?`, id).Scan(&item.ID, &item.Repo, &item.Reference, &item.Digest, &item.ContentType, &item.ManifestBody, &item.Status, &imageID, &item.DeletedAt, &item.RestoredAt)
	if imageID.Valid {
		item.ImageID = &imageID.Int64
	}
	return item, err
}

func (s *Store) DeleteRecycleItem(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM recycle_bin WHERE id=?`, id)
	return err
}

func (s *Store) MarkRecycleRestored(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE recycle_bin SET status='restored', restored_at=CURRENT_TIMESTAMP WHERE id=?`, id)
	return err
}

// ListPendingGC returns recycle_bin items with status='pending_gc'.
// When days > 0, only items older than N days are returned.
// When days <= 0, all pending items are returned.
func (s *Store) ListPendingGC(ctx context.Context, days int) ([]RecycleItem, error) {
	var query string
	var args []any
	if days > 0 {
		modifier := fmt.Sprintf("-%d days", days)
		query = `SELECT id,repo,reference,digest,content_type,status,image_id,deleted_at,COALESCE(restored_at,'') FROM recycle_bin WHERE status='pending_gc' AND deleted_at < datetime('now', ?) ORDER BY deleted_at ASC`
		args = append(args, modifier)
	} else {
		query = `SELECT id,repo,reference,digest,content_type,status,image_id,deleted_at,COALESCE(restored_at,'') FROM recycle_bin WHERE status='pending_gc' ORDER BY deleted_at ASC`
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RecycleItem
	for rows.Next() {
		var item RecycleItem
		var imageID sql.NullInt64
		if err := rows.Scan(&item.ID, &item.Repo, &item.Reference, &item.Digest, &item.ContentType, &item.Status, &imageID, &item.DeletedAt, &item.RestoredAt); err != nil {
			return nil, err
		}
		if imageID.Valid {
			item.ImageID = &imageID.Int64
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// User represents a UI user
type User struct {
	ID                 int64     `json:"id"`
	Username           string    `json:"username"`
	PasswordHash       string    `json:"-"`
	IsAdmin            bool      `json:"isAdmin"`
	Enabled            bool      `json:"enabled"`
	MustChangePassword bool      `json:"mustChangePassword"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

// UserPermission represents a namespace permission entry
type UserPermission struct {
	ID               int64     `json:"id"`
	UserID           int64     `json:"userId"`
	NamespacePattern string    `json:"namespacePattern"`
	CanRead          bool      `json:"canRead"`
	CanWrite         bool      `json:"canWrite"`
	CreatedAt        time.Time `json:"createdAt"`
}

// GetUserByUsername finds user by username
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	var isAdmin, enabled, mustChange int
	err := s.db.QueryRowContext(ctx, `SELECT id,username,password_hash,is_admin,enabled,password_must_change,created_at,updated_at FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &isAdmin, &enabled, &mustChange, &u.CreatedAt, &u.UpdatedAt)
	u.IsAdmin = isAdmin != 0
	u.Enabled = enabled != 0
	u.MustChangePassword = mustChange != 0
	return u, err
}

// GetUserByID finds user by ID
func (s *Store) GetUserByID(ctx context.Context, id int64) (User, error) {
	var u User
	var isAdmin, enabled, mustChange int
	err := s.db.QueryRowContext(ctx, `SELECT id,username,password_hash,is_admin,enabled,password_must_change,created_at,updated_at FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &isAdmin, &enabled, &mustChange, &u.CreatedAt, &u.UpdatedAt)
	u.IsAdmin = isAdmin != 0
	u.Enabled = enabled != 0
	u.MustChangePassword = mustChange != 0
	return u, err
}

// ListUsers lists all users
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,username,password_hash,is_admin,enabled,password_must_change,created_at,updated_at FROM users ORDER BY is_admin DESC, username ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var isAdmin, enabled, mustChange int
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &isAdmin, &enabled, &mustChange, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.IsAdmin = isAdmin != 0
		u.Enabled = enabled != 0
		u.MustChangePassword = mustChange != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) HasAdminUser(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE is_admin=1 AND enabled=1`).Scan(&count)
	return count > 0, err
}

// UpdateUser updates a user
func (s *Store) UpdateUser(ctx context.Context, id int64, username, password string, isAdmin, enabled bool) error {
	if password != "" {
		hash, err := HashPassword(password)
		if err != nil {
			return err
		}
		_, err = s.db.ExecContext(ctx, `UPDATE users SET username=?, password_hash=?, is_admin=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
			username, hash, boolInt(isAdmin), boolInt(enabled), id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET username=?, is_admin=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		username, boolInt(isAdmin), boolInt(enabled), id)
	return err
}

// DeleteUser deletes a user and all their permissions
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	// user_permissions and api_tokens are cleaned up automatically via
	// REFERENCES users(id) ON DELETE CASCADE.
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// ListUserPermissions lists permissions for a user
func (s *Store) ListUserPermissions(ctx context.Context, userID int64) ([]UserPermission, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,user_id,namespace_pattern,can_read,can_write,created_at FROM user_permissions WHERE user_id = ? ORDER BY namespace_pattern`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserPermission
	for rows.Next() {
		var p UserPermission
		var canRead, canWrite int
		if err := rows.Scan(&p.ID, &p.UserID, &p.NamespacePattern, &canRead, &canWrite, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.CanRead = canRead != 0
		p.CanWrite = canWrite != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreateUser adds a new user. If mustChangePassword is true the user is
// forced to change their password on next login.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash string, isAdmin, mustChangePassword bool) (User, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(username,password_hash,is_admin,password_must_change) VALUES(?,?,?,?)`, username, passwordHash, boolInt(isAdmin), boolInt(mustChangePassword))
	if err != nil {
		return User{}, err
	}
	return s.GetUserByUsername(ctx, username)
}

// UpdateUserPassword hashes and persists a new password for a user, then
// clears password_must_change so the change-password reminder goes away.
func (s *Store) UpdateUserPassword(ctx context.Context, id int64, newPassword string) error {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET password_hash=?, password_must_change=0, updated_at=CURRENT_TIMESTAMP WHERE id=?`, hash, id)
	return err
}

// SetUserPasswordHash sets a precomputed password hash without touching the
// password_must_change flag. Used for transparent legacy-to-bcrypt upgrades
// on login, which must not be treated as a deliberate password change.
func (s *Store) SetUserPasswordHash(ctx context.Context, id int64, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, hash, id)
	return err
}

// SetUserEnabled toggles the enabled flag. It only updates the enabled
// column, leaving username/isAdmin/password untouched. Use this for
// enable/disable toggles to avoid the foot-gun of full UpdateUser.
func (s *Store) SetUserEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, boolInt(enabled), id)
	return err
}

// CountEnabledAdmins returns the number of users that are both is_admin=1
// and enabled=1. Used by admin guards to prevent locking out the system.
func (s *Store) CountEnabledAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE is_admin=1 AND enabled=1`).Scan(&n)
	return n, err
}

// UpdateUserPermission updates a permission
func (s *Store) UpdateUserPermission(ctx context.Context, id int64, pattern string, canRead, canWrite bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE user_permissions SET namespace_pattern=?, can_read=?, can_write=? WHERE id=?`,
		pattern, boolInt(canRead), boolInt(canWrite), id)
	return err
}

// DeleteUserPermission deletes a permission
func (s *Store) DeleteUserPermission(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_permissions WHERE id = ?`, id)
	return err
}

// UpsertUserPermission inserts or updates a permission keyed by
// (user_id, namespace_pattern). The UNIQUE constraint makes the upsert
// idempotent, so repeated toggles on the same namespace never create
// duplicate rows.
func (s *Store) UpsertUserPermission(ctx context.Context, perm UserPermission) (UserPermission, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO user_permissions(user_id,namespace_pattern,can_read,can_write) VALUES(?,?,?,?)
		ON CONFLICT(user_id,namespace_pattern) DO UPDATE SET can_read=excluded.can_read, can_write=excluded.can_write`,
		perm.UserID, perm.NamespacePattern, boolInt(perm.CanRead), boolInt(perm.CanWrite))
	if err != nil {
		return UserPermission{}, err
	}
	if id, e := res.LastInsertId(); e == nil && id > 0 {
		perm.ID = id
	}
	return perm, nil
}

// DeleteUserPermissionByPattern removes a single user's permission for a
// specific namespace pattern. Used when a namespace is unchecked in the
// read column of the permission panel.
func (s *Store) DeleteUserPermissionByPattern(ctx context.Context, userID int64, pattern string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_permissions WHERE user_id = ? AND namespace_pattern = ?`, userID, pattern)
	return err
}

// ---- Immutable Tag Rules ----

func (s *Store) ListImmutableTagRules(ctx context.Context) ([]ImmutableTagRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,pattern,description,created_at FROM immutable_tag_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ImmutableTagRule
	for rows.Next() {
		var r ImmutableTagRule
		if err := rows.Scan(&r.ID, &r.Pattern, &r.Description, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateImmutableTagRule(ctx context.Context, r ImmutableTagRule) (ImmutableTagRule, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO immutable_tag_rules(pattern,description) VALUES(?,?)`, r.Pattern, r.Description)
	if err != nil {
		return ImmutableTagRule{}, err
	}
	id, _ := res.LastInsertId()
	r.ID = id
	return r, nil
}

func (s *Store) DeleteImmutableTagRule(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM immutable_tag_rules WHERE id=?`, id)
	return err
}

// ---- Repo Descriptions ----

func (s *Store) GetRepoDescription(ctx context.Context, repo string) (string, error) {
	var desc string
	err := s.db.QueryRowContext(ctx, `SELECT description FROM repo_descriptions WHERE repo=?`, repo).Scan(&desc)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return desc, err
}

func (s *Store) SetRepoDescription(ctx context.Context, repo, description string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO repo_descriptions(repo,description) VALUES(?,?) ON CONFLICT(repo) DO UPDATE SET description=excluded.description,updated_at=CURRENT_TIMESTAMP`, repo, description)
	return err
}

// ---- API Tokens ----

func (s *Store) CreateAPIToken(ctx context.Context, t APIToken) (APIToken, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO api_tokens(user_id,name,token_hash,token_prefix,description,expires_at) VALUES(?,?,?,?,?,?)`, t.UserID, t.Name, t.TokenHash, t.TokenPrefix, t.Description, t.ExpiresAt)
	if err != nil {
		return APIToken{}, err
	}
	id, _ := res.LastInsertId()
	t.ID = id
	return t, nil
}

func (s *Store) ListAPITokens(ctx context.Context, userID int64) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,user_id,name,token_prefix,description,expires_at,last_used_at,created_at FROM api_tokens WHERE user_id=? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var expires, lastUsed sql.NullTime
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenPrefix, &t.Description, &expires, &lastUsed, &t.CreatedAt); err != nil {
			return nil, err
		}
		if expires.Valid {
			t.ExpiresAt = &expires.Time
		}
		if lastUsed.Valid {
			t.LastUsedAt = &lastUsed.Time
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetAPITokenByPrefix(ctx context.Context, prefix string) (APIToken, error) {
	var t APIToken
	var expires, lastUsed sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id,user_id,name,token_hash,token_prefix,description,expires_at,last_used_at,created_at FROM api_tokens WHERE token_prefix=?`, prefix).
		Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.TokenPrefix, &t.Description, &expires, &lastUsed, &t.CreatedAt)
	if expires.Valid {
		t.ExpiresAt = &expires.Time
	}
	if lastUsed.Valid {
		t.LastUsedAt = &lastUsed.Time
	}
	return t, err
}

func (s *Store) DeleteAPIToken(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id=?`, id)
	return err
}

// GetAPITokenByID returns a token's metadata by id. The token_hash is loaded
// but unexported in JSON; callers use it for ownership checks before delete.
func (s *Store) GetAPITokenByID(ctx context.Context, id int64) (APIToken, error) {
	var t APIToken
	var expires, lastUsed sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id,user_id,name,token_hash,token_prefix,description,expires_at,last_used_at,created_at FROM api_tokens WHERE id=?`, id).
		Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.TokenPrefix, &t.Description, &expires, &lastUsed, &t.CreatedAt)
	if expires.Valid {
		t.ExpiresAt = &expires.Time
	}
	if lastUsed.Valid {
		t.LastUsedAt = &lastUsed.Time
	}
	return t, err
}

func (s *Store) TouchAPIToken(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE id=?`, id)
	return err
}

// ---- Repo Stats ----

func (s *Store) IncrementRepoPull(ctx context.Context, repo string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO repo_stats(repo,pull_count,last_pull_at) VALUES(?,1,CURRENT_TIMESTAMP) ON CONFLICT(repo) DO UPDATE SET pull_count=pull_count+1,last_pull_at=CURRENT_TIMESTAMP`, repo)
	return err
}

func (s *Store) IncrementRepoPush(ctx context.Context, repo string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO repo_stats(repo,push_count,last_push_at) VALUES(?,1,CURRENT_TIMESTAMP) ON CONFLICT(repo) DO UPDATE SET push_count=push_count+1,last_push_at=CURRENT_TIMESTAMP`, repo)
	return err
}

func (s *Store) ListRepoStats(ctx context.Context) ([]RepoStats, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT repo,pull_count,push_count,last_pull_at,last_push_at FROM repo_stats ORDER BY repo`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RepoStats
	for rows.Next() {
		var st RepoStats
		var lastPull, lastPush sql.NullTime
		if err := rows.Scan(&st.Repo, &st.PullCount, &st.PushCount, &lastPull, &lastPush); err != nil {
			return nil, err
		}
		if lastPull.Valid {
			st.LastPullAt = &lastPull.Time
		}
		if lastPush.Valid {
			st.LastPushAt = &lastPush.Time
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ---- Webhooks ----

func (s *Store) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,url,secret_header,events,enabled,created_at FROM webhooks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		var w Webhook
		var enabled int
		if err := rows.Scan(&w.ID, &w.URL, &w.SecretHeader, &w.Events, &enabled, &w.CreatedAt); err != nil {
			return nil, err
		}
		w.Enabled = enabled != 0
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) CreateWebhook(ctx context.Context, w Webhook) (Webhook, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO webhooks(url,secret_header,events,enabled) VALUES(?,?,?,?)`, w.URL, w.SecretHeader, w.Events, boolInt(w.Enabled))
	if err != nil {
		return Webhook{}, err
	}
	id, _ := res.LastInsertId()
	w.ID = id
	return w, nil
}

func (s *Store) UpdateWebhook(ctx context.Context, w Webhook) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webhooks SET url=?,secret_header=?,events=?,enabled=? WHERE id=?`, w.URL, w.SecretHeader, w.Events, boolInt(w.Enabled), w.ID)
	return err
}

func (s *Store) DeleteWebhook(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE id=?`, id)
	return err
}

// CleanupAllPendingGC deletes every recycle_bin row with status='pending_gc'
// regardless of age. Used by the manual GC button.
func (s *Store) CleanupAllPendingGC(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM recycle_bin WHERE status = 'pending_gc'`)
	if err != nil {
		return 0, err
	}
	affected, _ := res.RowsAffected()
	return int(affected), nil
}

// RunGC deletes recycle bin items older than the configured retention.
// recycleGCDays=0 disables automatic GC; invalid values fall back to 30.
func (s *Store) RunGC(ctx context.Context) int {
	days := s.GetSettingInt(ctx, "recycleGCDays", 30)
	if days < 0 {
		days = 30
	}
	if days == 0 {
		log.Printf("GC skipped: recycleGCDays=0 (disabled)")
		return 0
	}
	deleted, err := s.CleanupExpiredGC(ctx, days)
	if err != nil {
		log.Printf("GC failed: %v", err)
		return 0
	}
	log.Printf("GC completed: deleted %d expired items", deleted)
	return deleted
}

func (s *Store) CleanupExpiredGC(ctx context.Context, retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, errors.New("retention days must be > 0")
	}
	// SQLite datetime modifier needs to be a single string, can't be parameterized
	modifier := fmt.Sprintf("-%d days", retentionDays)
	res, err := s.db.ExecContext(ctx, `DELETE FROM recycle_bin WHERE status = 'pending_gc' AND deleted_at < datetime('now', ?)`, modifier)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	return int(affected), err
}

func (s *Store) GetPendingGCStats(ctx context.Context) (int, int64, error) {
	var count int
	var totalSize sql.NullInt64
	// Only count items whose digest is no longer referenced by any active (deleted=0) tag
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM recycle_bin rb WHERE status='pending_gc' AND NOT EXISTS (SELECT 1 FROM images i WHERE i.digest = rb.digest AND i.deleted = 0)`).Scan(&count, &totalSize)
	size := int64(0)
	if totalSize.Valid {
		size = totalSize.Int64
	}
	return count, size, err
}

func (s *Store) GetRepoPendingGCStats(ctx context.Context, repo string) (int, int64, error) {
	var count int
	var totalSize sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM recycle_bin rb WHERE status='pending_gc' AND repo=? AND NOT EXISTS (SELECT 1 FROM images i WHERE i.digest = rb.digest AND i.deleted = 0)`, repo).Scan(&count, &totalSize)
	size := int64(0)
	if totalSize.Valid {
		size = totalSize.Int64
	}
	return count, size, err
}

func (s *Store) GetRepoStats(ctx context.Context, repo string) (int, int64, error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid repo name: %s", repo)
	}
	var tagCount int
	var totalSize sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(i.size), 0) FROM images i JOIN repositories r ON i.repository_id = r.id JOIN namespaces n ON n.id = r.namespace_id WHERE n.name=? AND r.name=? AND i.deleted = 0`, parts[0], parts[1]).Scan(&tagCount, &totalSize)
	size := int64(0)
	if totalSize.Valid {
		size = totalSize.Int64
	}
	return tagCount, size, err
}

func (s *Store) GetGlobalImageStats(ctx context.Context) (int, int, int64, error) {
	var repoCount int
	var tagCount int
	var totalSize sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT r.id), COUNT(*), COALESCE(SUM(i.size), 0) FROM images i JOIN repositories r ON i.repository_id = r.id WHERE i.deleted = 0`).Scan(&repoCount, &tagCount, &totalSize)
	size := int64(0)
	if totalSize.Valid {
		size = totalSize.Int64
	}
	return repoCount, tagCount, size, err
}
