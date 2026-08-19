package main

import (
        "context"
        "fmt"
        "log"
        "time"

        "github.com/jackc/pgx/v5/pgxpool"
)

// DB is the global pgx pool.
var DB *pgxpool.Pool

// InitDB opens the connection pool and runs migrations + seeding.
func InitDB(cfg *Config) {
        var err error
        DB, err = pgxpool.New(context.Background(), cfg.PGConnString)
        if err != nil {
                log.Fatalf("[fatal] cannot connect to PostgreSQL: %v", err)
        }
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        if err := DB.Ping(ctx); err != nil {
                log.Fatalf("[fatal] DB ping failed: %v", err)
        }
        log.Printf("[info] connected to PostgreSQL %s on %s:%d", cfg.PGDBName, cfg.PGHost, cfg.PGPort)
        runMigrations(cfg)
}

func runMigrations(cfg *Config) {
        stmts := []string{
                `CREATE TABLE IF NOT EXISTS users (
                        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        username        TEXT NOT NULL UNIQUE,
                        key_hash        TEXT NOT NULL UNIQUE,
                        key_prefix      TEXT NOT NULL,
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                        is_banned       BOOLEAN NOT NULL DEFAULT FALSE,
                        banned_reason   TEXT,
                        banned_until    TIMESTAMPTZ,
                        theme           TEXT NOT NULL DEFAULT 'dark'
                );`,

                `CREATE TABLE IF NOT EXISTS threads (
                        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        slug            TEXT NOT NULL UNIQUE,
                        name            TEXT NOT NULL,
                        description     TEXT NOT NULL DEFAULT '',
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                        is_active       BOOLEAN NOT NULL DEFAULT TRUE,
                        sort_order      INTEGER NOT NULL DEFAULT 0
                );`,

                `CREATE TABLE IF NOT EXISTS posts (
                        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        thread_id       UUID NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
                        user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        parent_post_id  UUID REFERENCES posts(id) ON DELETE CASCADE,
                        is_op           BOOLEAN NOT NULL DEFAULT FALSE,
                        title           TEXT NOT NULL DEFAULT '',
                        body            TEXT NOT NULL DEFAULT '',
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                        upvotes         INTEGER NOT NULL DEFAULT 0,
                        reply_count     INTEGER NOT NULL DEFAULT 0
                );`,
                `CREATE EXTENSION IF NOT EXISTS ltree;`,
                `ALTER TABLE posts ADD COLUMN IF NOT EXISTS path ltree;`,
                `CREATE INDEX IF NOT EXISTS idx_posts_thread_created ON posts(thread_id, created_at DESC);`,
                `CREATE INDEX IF NOT EXISTS idx_posts_parent ON posts(parent_post_id);`,
                `CREATE INDEX IF NOT EXISTS idx_posts_path ON posts USING gist(path);`,
                `CREATE INDEX IF NOT EXISTS idx_posts_thread_upvotes ON posts(thread_id, upvotes DESC);`,

                `CREATE TABLE IF NOT EXISTS attachments (
                        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        post_id         UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                        file_path       TEXT NOT NULL,
                        file_name       TEXT NOT NULL,
                        mime_type       TEXT NOT NULL,
                        file_size       BIGINT NOT NULL,
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
                );`,
                `CREATE INDEX IF NOT EXISTS idx_attachments_post ON attachments(post_id);`,

                `CREATE TABLE IF NOT EXISTS hashtags (
                        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        tag             TEXT NOT NULL UNIQUE,
                        usage_count     INTEGER NOT NULL DEFAULT 0
                );`,
                `CREATE TABLE IF NOT EXISTS post_hashtags (
                        post_id         UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                        hashtag_id     UUID NOT NULL REFERENCES hashtags(id) ON DELETE CASCADE,
                        PRIMARY KEY (post_id, hashtag_id)
                );`,
                `CREATE INDEX IF NOT EXISTS idx_post_hashtags_tag ON post_hashtags(hashtag_id);`,

                `CREATE TABLE IF NOT EXISTS messages (
                        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        from_user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
                        to_user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
                        body            TEXT NOT NULL,
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                        is_read         BOOLEAN NOT NULL DEFAULT FALSE
                );`,
                `CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(from_user_id, to_user_id, created_at DESC);`,
                `CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_user_id, created_at DESC);`,
                `CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_user_id, created_at DESC);`,

                `CREATE TABLE IF NOT EXISTS pow_challenges (
                        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        challenge       TEXT NOT NULL UNIQUE,
                        purpose         TEXT NOT NULL,
                        expires_at      TIMESTAMPTZ NOT NULL,
                        used            BOOLEAN NOT NULL DEFAULT FALSE,
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
                );`,
                `CREATE INDEX IF NOT EXISTS idx_pow_expires ON pow_challenges(expires_at);`,

                `CREATE TABLE IF NOT EXISTS settings (
                        key             TEXT PRIMARY KEY,
                        value           TEXT NOT NULL,
                        updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
                );`,

                `CREATE TABLE IF NOT EXISTS admin_sessions (
                        token           TEXT PRIMARY KEY,
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                        expires_at      TIMESTAMPTZ NOT NULL
                );`,

                // Drop and recreate messages table with the new schema (no to_admin column,
                // from_user_id nullable for admin-originated messages). Old data is test-only.
                `DROP TABLE IF EXISTS messages;`,
                `CREATE TABLE messages (
                        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        from_user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
                        to_user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
                        body            TEXT NOT NULL,
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                        is_read         BOOLEAN NOT NULL DEFAULT FALSE,
                        CONSTRAINT msg_direction CHECK (
                                (from_user_id IS NOT NULL AND to_user_id IS NULL) OR
                                (from_user_id IS NULL AND to_user_id IS NOT NULL) OR
                                (from_user_id IS NOT NULL AND to_user_id IS NOT NULL)
                        )
                );`,
                `CREATE INDEX idx_messages_thread ON messages(from_user_id, to_user_id, created_at DESC);`,
                `CREATE INDEX idx_messages_to ON messages(to_user_id, created_at DESC);`,
                `CREATE INDEX idx_messages_from ON messages(from_user_id, created_at DESC);`,
        }
        for i, s := range stmts {
                if _, err := DB.Exec(context.Background(), s); err != nil {
                        log.Printf("[warn] migration %d failed: %v | stmt: %s", i, err, truncate(s, 200))
                }
        }

        // Seed initial threads if none exist.
        var count int
        if err := DB.QueryRow(context.Background(), `SELECT COUNT(*) FROM threads`).Scan(&count); err != nil {
                log.Fatalf("[fatal] cannot count threads: %v", err)
        }
        if count == 0 {
                for i, t := range cfg.InitialThreads {
                        _, err := DB.Exec(context.Background(),
                                `INSERT INTO threads (slug, name, description, sort_order) VALUES ($1, $2, $3, $4)`,
                                t.Slug, t.Name, t.Description, i)
                        if err != nil {
                                log.Printf("[warn] seed thread %s failed: %v", t.Slug, err)
                        }
                }
                log.Printf("[info] seeded %d initial threads", len(cfg.InitialThreads))
        }

        // Seed default settings.
        defaults := map[string]string{
                "pow_register_bits":    fmt.Sprintf("%d", cfg.PowRegisterBits),
                "pow_login_bits":       fmt.Sprintf("%d", cfg.PowLoginBits),
                "pow_post_bits":        fmt.Sprintf("%d", cfg.PowPostBits),
                "pow_reply_bits":       fmt.Sprintf("%d", cfg.PowReplyBits),
                "pow_message_bits":     fmt.Sprintf("%d", cfg.PowMessageBits),
                "max_upload_mb":        fmt.Sprintf("%d", cfg.MaxUploadBytes/1024/1024),
                "max_attachments":      fmt.Sprintf("%d", cfg.MaxAttachments),
                "site_theme":           "dark",
                "site_accent":          "#8b5cf6",
                "site_bg_dark":         "#1a1033",
                "site_text_dark":       "#e5e0f5",
                "site_bg_light":        "#faf7ff",
                "site_text_light":      "#2d1b4e",
                "site_name":            "libtd.com",
        }
        for k, v := range defaults {
                _, err := DB.Exec(context.Background(),
                        `INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, k, v)
                if err != nil {
                        log.Printf("[warn] seed setting %s failed: %v", k, err)
                }
        }

        // Cleanup expired PoW challenges older than 1 hour (best-effort).
        _, _ = DB.Exec(context.Background(), `DELETE FROM pow_challenges WHERE expires_at < now() - interval '1 hour'`)
}

func truncate(s string, n int) string {
        if len(s) <= n {
                return s
        }
        return s[:n] + "..."
}
