package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ctxBackground is a convenience wrapper for fire-and-forget DB ops.
func ctxBackground() context.Context { return context.Background() }

// UserClaims is what we store inside the JWT we hand to logged-in users.
type UserClaims struct {
	UserID   string `json:"uid"`
	Username string `json:"uname"`
	jwt.RegisteredClaims
}

// AuthMiddleware extracts and validates the user JWT, attaches user info to the context.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		token := ""
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// also accept cookie for convenience
			if ck, err := c.Cookie("libtd_token"); err == nil && ck != "" {
				token = ck
			}
		}
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "auth required"})
			return
		}
		claims := &UserClaims{}
		parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(AppConfig.JWTSecret), nil
		})
		if err != nil || !parsed.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Next()
	}
}

// AdminAuthMiddleware validates the admin session token (cookie).
func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("libtd_admin")
		if err != nil || token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "admin login required"})
			return
		}
		var exp time.Time
		err = DB.QueryRow(ctxBackground(),
			`SELECT expires_at FROM admin_sessions WHERE token = $1`, token).Scan(&exp)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid admin session"})
			return
		}
		if time.Now().After(exp) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "admin session expired"})
			return
		}
		c.Set("admin_token", token)
		c.Next()
	}
}

// CORSMiddleware adds permissive CORS for our React dev origin.
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		allowed := false
		for _, o := range AppConfig.CORSOrigins {
			if o == origin {
				allowed = true
				break
			}
		}
		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// validateUUID returns true if the string parses as a UUID.
func validateUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}
