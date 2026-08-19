package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all server configuration loaded from .env.
type Config struct {
	PGHost         string
	PGPort         int
	PGUser         string
	PGPassword     string
	PGDBName       string
	PGConnString   string
	ServerPort     int
	UploadsDir     string
	MaxUploadBytes int64
	MaxAttachments int
	AllowedMimes   []string

	AdminUsername string
	AdminPassword string

	JWTSecret   string
	JWTTTLHours int

	PowRegisterBits int
	PowLoginBits    int
	PowPostBits     int
	PowReplyBits    int
	PowMessageBits  int

	InitialThreads []ThreadSeed

	CORSOrigins []string
}

// ThreadSeed describes an initial board to create on first run.
type ThreadSeed struct {
	Slug        string
	Name        string
	Description string
}

// LoadConfig loads .env and computes derived values.
func LoadConfig() *Config {
	if err := godotenv.Load("../.env"); err != nil {
		log.Printf("[warn] .env not loaded: %v (using env defaults)", err)
	}
	c := &Config{
		PGHost:          getenv("PG_HOST", "/home/z/pgdata"),
		PGPort:          getenvInt("PG_PORT", 15432),
		PGUser:          getenv("PG_USER", "libtd_user"),
		PGPassword:      getenv("PG_PASSWORD", "libtd_secure_pass_2026"),
		PGDBName:        getenv("PG_DBNAME", "libtd_db"),
		ServerPort:      getenvInt("SERVER_PORT", 8080),
		UploadsDir:      getenv("UPLOADS_DIR", "/home/z/my-project/uploads"),
		MaxUploadBytes:  int64(getenvInt("MAX_UPLOAD_MB", 50)) * 1024 * 1024,
		MaxAttachments:  getenvInt("MAX_ATTACHMENTS", 4),
		AdminUsername:   getenv("ADMIN_USERNAME", "libtd_admin"),
		AdminPassword:   getenv("ADMIN_PASSWORD", "change_me_in_production_2026"),
		JWTSecret:       getenv("JWT_SECRET", "libtd-jwt-super-secret-2026-please-change-9f3a2b1c8e7d4f6a"),
		JWTTTLHours:     getenvInt("JWT_TTL_HOURS", 720),
		PowRegisterBits: getenvInt("POW_REGISTER_BITS", 20),
		PowLoginBits:    getenvInt("POW_LOGIN_BITS", 16),
		PowPostBits:     getenvInt("POW_POST_BITS", 18),
		PowReplyBits:    getenvInt("POW_REPLY_BITS", 16),
		PowMessageBits:  getenvInt("POW_MESSAGE_BITS", 14),
	}
	c.AllowedMimes = strings.Split(getenv("ALLOWED_MIME", "image/jpeg,image/png,image/gif,image/webp,video/mp4,video/webm,application/pdf,text/plain"), ",")
	c.PGConnString = fmt.Sprintf("postgres://%s:%s@/%s?host=%s&port=%d&sslmode=disable",
		c.PGUser, c.PGPassword, c.PGDBName, c.PGHost, c.PGPort)
	seedRaw := getenv("INITIAL_THREADS", "b/,Random,Random discussion|g/,Tech,Technology and programming|pol/,Politics,Politics and news|c/,Culture,Art, music, literature|mt/,Meta,Discussion about the site")
	for _, item := range strings.Split(seedRaw, "|") {
		parts := strings.SplitN(item, ",", 3)
		if len(parts) < 2 {
			continue
		}
		desc := ""
		if len(parts) == 3 {
			desc = parts[2]
		}
		c.InitialThreads = append(c.InitialThreads, ThreadSeed{Slug: parts[0], Name: parts[1], Description: desc})
	}
	c.CORSOrigins = strings.Split(getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"), ",")
	return c
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
