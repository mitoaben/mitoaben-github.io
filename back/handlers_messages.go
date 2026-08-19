package main

import (
        "database/sql"
        "net/http"
        "strings"
        "time"

        "github.com/gin-gonic/gin"
        "github.com/google/uuid"
        "github.com/jackc/pgx/v5"
)

// ============================ Messaging ============================
//
// Clean model:
//   from_user_id  = who sent the message. NULL = admin.
//   to_user_id    = recipient. NULL = admin.
//
// Three valid combinations:
//   1. user -> admin:  from=me,    to=NULL
//   2. admin -> user:  from=NULL,  to=me
//   3. user -> user:   from=me,    to=other
//
// "Admin" is not a real row in the users table; it's the implicit role
// authenticated via the admin cookie. Conversations are grouped by the
// (from_user_id, to_user_id) pair in either direction.
//
// Endpoints:
//   GET  /api/messages/conversations          -> list partners for current user
//   GET  /api/messages/with/:partner          -> conversation with a partner
//                                                (partner = "admin" or a user UUID)
//   GET  /api/messages/challenge              -> PoW challenge for sending
//   POST /api/messages/send                   -> send a message (PoW required)
//
//   GET  /api/users/search?q=foo             -> find a user by username (for "new message")

type sendMessageRequest struct {
        ToUserID  string `json:"to_user_id"`  // empty = send to admin
        Body      string `json:"body" binding:"required,max=8000"`
        Challenge string `json:"challenge" binding:"required"`
        Nonce     uint64 `json:"nonce"`
}

// SendMessageChallengeHandler issues a PoW challenge bound to (sender, recipient).
// Query params: to_user_id (optional; if empty, target = admin).
func SendMessageChallengeHandler(c *gin.Context) {
        uidAny, _ := c.Get("user_id")
        uid, _ := uidAny.(string)
        toUserID := strings.TrimSpace(c.Query("to_user_id"))
        payloadHint := uid + "|" + toUserID
        ch, err := IssueChallenge(PurposeMessage, payloadHint)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "challenge issue failed"})
                return
        }
        c.JSON(http.StatusOK, ch)
}

// SendMessageHandler sends a message. PoW purpose = "message".
// If to_user_id is empty, the message goes to admin (to_user_id = NULL).
func SendMessageHandler(c *gin.Context) {
        uidAny, _ := c.Get("user_id")
        uid, _ := uidAny.(string)
        var req sendMessageRequest
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        req.ToUserID = strings.TrimSpace(req.ToUserID)
        // Validate: either a real user UUID or empty (= admin).
        if req.ToUserID != "" && !validateUUID(req.ToUserID) {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to_user_id"})
                return
        }
        // Don't allow self-messaging.
        if req.ToUserID == uid {
                c.JSON(http.StatusBadRequest, gin.H{"error": "cannot message yourself"})
                return
        }
        // Verify PoW.
        payloadHint := uid + "|" + req.ToUserID
        if err := VerifyPoW(req.Challenge, req.Nonce, payloadHint, PurposeMessage); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": "PoW invalid: " + err.Error()})
                return
        }
        // If user-to-user, ensure target exists and is not banned.
        if req.ToUserID != "" {
                var exists bool
                _ = DB.QueryRow(ctxBackground(),
                        `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid AND is_banned=FALSE)`, req.ToUserID).Scan(&exists)
                if !exists {
                        c.JSON(http.StatusNotFound, gin.H{"error": "recipient not found"})
                        return
                }
        }
        // Insert. to_user_id is NULL when sending to admin.
        var toID any
        if req.ToUserID != "" {
                toID = req.ToUserID
        }
        id := uuid.NewString()
        _, err := DB.Exec(ctxBackground(),
                `INSERT INTO messages (id, from_user_id, to_user_id, body) VALUES ($1, $2::uuid, $3, $4)`,
                id, uid, toID, req.Body)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "send failed: " + err.Error()})
                return
        }
        c.JSON(http.StatusCreated, gin.H{"id": id, "body": req.Body, "created_at": time.Now().UTC()})
}

type messageDTO struct {
        ID         string   `json:"id"`
        FromUserID *string  `json:"from_user_id"`
        FromName   string   `json:"from_username"`
        ToUserID   *string  `json:"to_user_id"`
        ToName     string   `json:"to_username"`
        Body       string   `json:"body"`
        CreatedAt  time.Time `json:"created_at"`
        IsRead     bool     `json:"is_read"`
        Mine       bool     `json:"mine"`
}

// conversationDTO describes a single conversation partner for the listing endpoint.
type conversationDTO struct {
        PartnerID   string    `json:"partner_id"`   // "" for admin chat, else partner's UUID
        PartnerName string    `json:"partner_name"` // "admin" or username
        LastBody    string    `json:"last_body"`
        LastAt      time.Time `json:"last_at"`
        Unread      int       `json:"unread"`
}

// ListConversationsHandler returns distinct conversation partners for the logged-in user.
//
// Partner = the OTHER party:
//   - if I'm the sender (from = me), partner = to_user_id (NULL = admin)
//   - if I'm the recipient (to = me), partner = from_user_id (NULL = admin)
//
// All messages where one side is admin (NULL user_id on either side) are grouped
// into a single "admin" conversation with partner_id = "".
func ListConversationsHandler(c *gin.Context) {
        uidAny, _ := c.Get("user_id")
        uid, _ := uidAny.(string)
        // We compute partner_id per message as a string (or empty for admin),
        // then group by partner_id.
        rows, err := DB.Query(ctxBackground(), `
                WITH partner_msgs AS (
                        SELECT
                                *,
                                CASE
                                        WHEN from_user_id::text = $1 THEN COALESCE(to_user_id::text, '')
                                        ELSE COALESCE(from_user_id::text, '')
                                END AS partner_id,
                                CASE
                                        WHEN (from_user_id::text = $1 AND to_user_id IS NULL)
                                          OR (to_user_id::text = $1 AND from_user_id IS NULL) THEN 'admin'
                                        WHEN from_user_id::text = $1 THEN (SELECT username FROM users WHERE id = to_user_id)
                                        ELSE (SELECT username FROM users WHERE id = from_user_id)
                                END AS partner_name,
                                CASE WHEN to_user_id::text = $1 THEN TRUE ELSE FALSE END AS incoming
                        FROM messages
                        WHERE from_user_id::text = $1 OR to_user_id::text = $1
                )
                SELECT
                        partner_id,
                        MAX(partner_name) AS partner_name,
                        (SELECT body FROM partner_msgs pm2 WHERE pm2.partner_id = pm.partner_id ORDER BY created_at DESC LIMIT 1) AS last_body,
                        MAX(created_at) AS last_at,
                        COUNT(*) FILTER (WHERE incoming = TRUE AND is_read = FALSE) AS unread
                FROM partner_msgs pm
                GROUP BY partner_id
                ORDER BY last_at DESC NULLS LAST`, uid)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        out := []conversationDTO{}
        for rows.Next() {
                var pID, pName, lastBody sql.NullString
                var lastAt sql.NullTime
                var unread int
                if err := rows.Scan(&pID, &pName, &lastBody, &lastAt, &unread); err != nil {
                        continue
                }
                out = append(out, conversationDTO{
                        PartnerID:   pID.String,
                        PartnerName: pName.String,
                        LastBody:    lastBody.String,
                        LastAt:      lastAt.Time,
                        Unread:      unread,
                })
        }
        c.JSON(http.StatusOK, gin.H{"conversations": out})
}

// GetConversationHandler returns messages with a specific partner.
// GET /api/messages/with/:partner
//   partner = "admin"  -> messages between me and admin (both directions)
//   partner = UUID     -> messages between me and that user (both directions)
func GetConversationHandler(c *gin.Context) {
        uidAny, _ := c.Get("user_id")
        uid, _ := uidAny.(string)
        partner := c.Param("partner")
        if partner == "" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "partner required"})
                return
        }
        var rows pgx.Rows
        var err error
        if partner == "admin" {
                // All messages where I sent to admin OR admin sent to me.
                rows, err = DB.Query(ctxBackground(), `
                        SELECT m.id, m.from_user_id, COALESCE(uf.username, ''), m.to_user_id, COALESCE(ut.username, ''), m.body, m.created_at, m.is_read
                        FROM messages m
                        LEFT JOIN users uf ON uf.id = m.from_user_id
                        LEFT JOIN users ut ON ut.id = m.to_user_id
                        WHERE (m.from_user_id::text = $1 AND m.to_user_id IS NULL)
                           OR (m.to_user_id::text = $1 AND m.from_user_id IS NULL)
                        ORDER BY m.created_at ASC`, uid)
        } else {
                if !validateUUID(partner) {
                        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid partner id"})
                        return
                }
                rows, err = DB.Query(ctxBackground(), `
                        SELECT m.id, m.from_user_id, COALESCE(uf.username, ''), m.to_user_id, COALESCE(ut.username, ''), m.body, m.created_at, m.is_read
                        FROM messages m
                        LEFT JOIN users uf ON uf.id = m.from_user_id
                        LEFT JOIN users ut ON ut.id = m.to_user_id
                        WHERE (m.from_user_id::text = $1 AND m.to_user_id::text = $2)
                           OR (m.from_user_id::text = $2 AND m.to_user_id::text = $1)
                        ORDER BY m.created_at ASC`, uid, partner)
        }
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        out := []messageDTO{}
        for rows.Next() {
                var m messageDTO
                if err := rows.Scan(&m.ID, &m.FromUserID, &m.FromName, &m.ToUserID, &m.ToName, &m.Body, &m.CreatedAt, &m.IsRead); err == nil {
                        m.Mine = m.FromUserID != nil && *m.FromUserID == uid
                        out = append(out, m)
                }
        }
        // Mark as read the ones addressed to me.
        if partner == "admin" {
                _, _ = DB.Exec(ctxBackground(),
                        `UPDATE messages SET is_read=TRUE WHERE to_user_id::text=$1 AND from_user_id IS NULL`, uid)
        } else {
                _, _ = DB.Exec(ctxBackground(),
                        `UPDATE messages SET is_read=TRUE WHERE to_user_id::text=$1 AND from_user_id::text=$2`, uid, partner)
        }
        c.JSON(http.StatusOK, gin.H{"messages": out})
}

// UserSearchHandler finds users by username prefix (for messaging).
// GET /api/users/search?q=foo&limit=10
func UserSearchHandler(c *gin.Context) {
        q := strings.TrimSpace(c.Query("q"))
        limit := parseIntDefault(c.Query("limit"), 10)
        if limit < 1 || limit > 50 {
                limit = 10
        }
        if len(q) < 2 {
                c.JSON(http.StatusOK, gin.H{"users": []any{}})
                return
        }
        uidAny, _ := c.Get("user_id")
        uid, _ := uidAny.(string)
        rows, err := DB.Query(ctxBackground(), `
                SELECT id, username FROM users
                WHERE username ILIKE $1
                  AND id::text <> $2
                  AND is_banned = FALSE
                ORDER BY username ASC
                LIMIT $3`, "%"+q+"%", uid, limit)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        type u struct {
                ID       string `json:"id"`
                Username string `json:"username"`
        }
        out := []u{}
        for rows.Next() {
                var x u
                _ = rows.Scan(&x.ID, &x.Username)
                out = append(out, x)
        }
        c.JSON(http.StatusOK, gin.H{"users": out})
}

var _ = strings.TrimSpace
var _ = sql.NullString{}
