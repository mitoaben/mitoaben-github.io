package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ============================ Registration ============================

type registerRequest struct {
	Username  string `json:"username" binding:"required,min=3,max=32"`
	Challenge string `json:"challenge" binding:"required"`
	Nonce     uint64 `json:"nonce"`
}

// RegisterHandler issues a challenge (GET) or finalizes registration (POST).
// GET /api/auth/register/challenge?username=foo
// POST /api/auth/register {username, challenge, nonce}
func RegisterChallengeHandler(c *gin.Context) {
	username := strings.TrimSpace(c.Query("username"))
	if len(username) < 3 || len(username) > 32 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username must be 3-32 chars"})
		return
	}
	if !validUsername(username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username contains invalid characters"})
		return
	}
	// Check uniqueness early so the client doesn't mine for nothing.
	var exists bool
	_ = DB.QueryRow(ctxBackground(), `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)`, username).Scan(&exists)
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "username already taken"})
		return
	}
	ch, err := IssueChallenge(PurposeRegister, PayloadDigest(username))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "challenge issue failed"})
		return
	}
	c.JSON(http.StatusOK, ch)
}

func RegisterHandler(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validUsername(req.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid username"})
		return
	}
	if err := VerifyPoW(req.Challenge, req.Nonce, PayloadDigest(req.Username), PurposeRegister); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PoW invalid: " + err.Error()})
		return
	}
	// Generate the unique key: "libtd-" + 64 hex chars (32 bytes of entropy).
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "key generation failed"})
		return
	}
	key := "libtd-" + hex.EncodeToString(keyBytes)
	keyHash := hashKey(key)
	keyPrefix := key[:14] // "libtd-7f3a9b2c1e8d"

	var exists bool
	_ = DB.QueryRow(ctxBackground(), `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)`, req.Username).Scan(&exists)
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "username already taken"})
		return
	}

	uid, err := uuid.NewUUID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "uuid failed"})
		return
	}
	_, err = DB.Exec(ctxBackground(),
		`INSERT INTO users (id, username, key_hash, key_prefix) VALUES ($1, $2, $3, $4)`,
		uid, req.Username, keyHash, keyPrefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"user_id":    uid.String(),
		"username":   req.Username,
		"key":        key,
		"key_prefix": keyPrefix,
		"warning":    "Save this key securely. It will not be shown again. Anyone with the key can access your account.",
	})
}

// ============================ Login ============================

type loginRequest struct {
	Username  string `json:"username" binding:"required"`
	Key       string `json:"key" binding:"required"`
	Challenge string `json:"challenge" binding:"required"`
	Nonce     uint64 `json:"nonce"`
}

func LoginChallengeHandler(c *gin.Context) {
	username := strings.TrimSpace(c.Query("username"))
	key := strings.TrimSpace(c.Query("key"))
	if username == "" || key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and key required"})
		return
	}
	ch, err := IssueChallenge(PurposeLogin, PayloadDigest(username+":"+key))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "challenge issue failed"})
		return
	}
	c.JSON(http.StatusOK, ch)
}

func LoginHandler(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := VerifyPoW(req.Challenge, req.Nonce, PayloadDigest(req.Username+":"+req.Key), PurposeLogin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PoW invalid: " + err.Error()})
		return
	}
	keyHash := hashKey(req.Key)
	var (
		uid      string
		uname    string
		isBanned bool
		theme    string
	)
	err := DB.QueryRow(ctxBackground(),
		`SELECT id, username, is_banned, theme FROM users WHERE username=$1 AND key_hash=$2`,
		req.Username, keyHash).Scan(&uid, &uname, &isBanned, &theme)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if isBanned {
		c.JSON(http.StatusForbidden, gin.H{"error": "user is banned"})
		return
	}
	token, err := issueUserJWT(uid, uname)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token issue failed"})
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("libtd_token", token, AppConfig.JWTTTLHours*3600, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"user_id":  uid,
		"username": uname,
		"theme":    theme,
	})
}

// ============================ Admin login ============================

type adminLoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func AdminLoginHandler(c *gin.Context) {
	var req adminLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Username != AppConfig.AdminUsername || req.Password != AppConfig.AdminPassword {
		// constant-time-ish small delay to slow brute force; no rate limit in this build
		time.Sleep(300 * time.Millisecond)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid admin credentials"})
		return
	}
	// generate session token
	tokBytes := make([]byte, 32)
	if _, err := rand.Read(tokBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "rand failed"})
		return
	}
	tok := hex.EncodeToString(tokBytes)
	expires := time.Now().Add(time.Duration(AppConfig.JWTTTLHours) * time.Hour)
	_, err := DB.Exec(ctxBackground(),
		`INSERT INTO admin_sessions (token, expires_at) VALUES ($1, $2)`,
		tok, expires)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session save failed"})
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("libtd_admin", tok, AppConfig.JWTTTLHours*3600, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"token": tok, "expires_at": expires})
}

func AdminLogoutHandler(c *gin.Context) {
	tok, _ := c.Get("admin_token")
	if tok != nil {
		_, _ = DB.Exec(ctxBackground(), `DELETE FROM admin_sessions WHERE token=$1`, tok)
	}
	c.SetCookie("libtd_admin", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ============================ Helpers ============================

func issueUserJWT(uid, uname string) (string, error) {
	claims := UserClaims{
		UserID:   uid,
		Username: uname,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(AppConfig.JWTTTLHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   uid,
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(AppConfig.JWTSecret))
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func validUsername(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '-':
			continue
		default:
			return false
		}
	}
	if strings.HasPrefix(strings.ToLower(s), "admin") {
		return false
	}
	return true
}

// MeHandler returns info about the currently logged-in user.
func MeHandler(c *gin.Context) {
	uid, _ := c.Get("user_id")
	uname, _ := c.Get("username")
	c.JSON(http.StatusOK, gin.H{
		"user_id":  uid,
		"username": uname,
	})
}

// LogoutHandler clears the auth cookie.
func LogoutHandler(c *gin.Context) {
	c.SetCookie("libtd_token", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

var _ = fmt.Sprintf
