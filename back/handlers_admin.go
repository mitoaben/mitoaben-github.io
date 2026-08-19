package main

import (
        "net/http"
        "strconv"
        "strings"
        "time"

        "github.com/gin-gonic/gin"
        "github.com/google/uuid"
)

// ============================ Admin API ============================
//
// All endpoints under /api/admin/* require a valid admin session cookie.
//
//   GET    /api/admin/threads                   -> list threads
//   POST   /api/admin/threads                   -> create thread
//   PATCH  /api/admin/threads/:id               -> update thread
//   DELETE /api/admin/threads/:id               -> delete thread
//
//   GET    /api/admin/users                     -> list users
//   DELETE /api/admin/users/:id                  -> delete user
//   PATCH  /api/admin/users/:id                  -> ban / unban / set theme
//
//   GET    /api/admin/settings                   -> get all settings
//   PUT    /api/admin/settings                    -> update settings (json body)
//
//   GET    /api/admin/messages                   -> list of conversations initiated by users to admin
//   GET    /api/admin/messages/:user_id          -> messages between admin and a specific user
//   POST   /api/admin/messages/:user_id          -> admin replies to a user

type adminThreadRequest struct {
        Slug        string `json:"slug"`
        Name        string `json:"name"`
        Description string `json:"description"`
        IsActive    *bool  `json:"is_active"`
        SortOrder   *int   `json:"sort_order"`
}

func AdminListThreadsHandler(c *gin.Context) {
        rows, err := DB.Query(ctxBackground(),
                `SELECT id, slug, name, description, is_active, sort_order, created_at FROM threads ORDER BY sort_order, created_at`)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        type t struct {
                ID          string    `json:"id"`
                Slug        string    `json:"slug"`
                Name        string    `json:"name"`
                Description string    `json:"description"`
                IsActive    bool      `json:"is_active"`
                SortOrder   int       `json:"sort_order"`
                CreatedAt   time.Time `json:"created_at"`
        }
        out := []t{}
        for rows.Next() {
                var x t
                _ = rows.Scan(&x.ID, &x.Slug, &x.Name, &x.Description, &x.IsActive, &x.SortOrder, &x.CreatedAt)
                out = append(out, x)
        }
        c.JSON(http.StatusOK, gin.H{"threads": out})
}

func AdminCreateThreadHandler(c *gin.Context) {
        var req adminThreadRequest
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        // strip any trailing '/' so URL routing stays simple
        req.Slug = strings.TrimRight(req.Slug, "/")
        if req.Slug == "" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "slug required"})
                return
        }
        id := uuid.NewString()
        _, err := DB.Exec(ctxBackground(),
                `INSERT INTO threads (id, slug, name, description, is_active, sort_order) VALUES ($1,$2,$3,$4,COALESCE($5,TRUE),COALESCE($6,0))`,
                id, req.Slug, req.Name, req.Description, req.IsActive, req.SortOrder)
        if err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        c.JSON(http.StatusCreated, gin.H{"id": id, "slug": req.Slug, "name": req.Name})
}

func AdminUpdateThreadHandler(c *gin.Context) {
        id := c.Param("id")
        var req adminThreadRequest
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        _, err := DB.Exec(ctxBackground(), `
                UPDATE threads SET
                  slug=COALESCE(NULLIF($2,''), slug),
                  name=COALESCE(NULLIF($3,''), name),
                  description=COALESCE($4, description),
                  is_active=COALESCE($5, is_active),
                  sort_order=COALESCE($6, sort_order)
                WHERE id=$1`,
                id, req.Slug, req.Name, req.Description, req.IsActive, req.SortOrder)
        if err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        c.JSON(http.StatusOK, gin.H{"ok": true})
}

func AdminDeleteThreadHandler(c *gin.Context) {
        id := c.Param("id")
        _, err := DB.Exec(ctxBackground(), `DELETE FROM threads WHERE id=$1`, id)
        if err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ============================ Users ============================

func AdminListUsersHandler(c *gin.Context) {
        page := parseIntDefault(c.Query("page"), 1)
        per := parseIntDefault(c.Query("per"), 50)
        offset := (page - 1) * per
        rows, err := DB.Query(ctxBackground(), `
                SELECT id, username, key_prefix, created_at, is_banned, banned_reason, banned_until, theme
                FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`, per, offset)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        type u struct {
                ID           string     `json:"id"`
                Username     string     `json:"username"`
                KeyPrefix    string     `json:"key_prefix"`
                CreatedAt    time.Time  `json:"created_at"`
                IsBanned     bool       `json:"is_banned"`
                BannedReason *string    `json:"banned_reason,omitempty"`
                BannedUntil  *time.Time `json:"banned_until,omitempty"`
                Theme        string     `json:"theme"`
        }
        out := []u{}
        for rows.Next() {
                var x u
                _ = rows.Scan(&x.ID, &x.Username, &x.KeyPrefix, &x.CreatedAt, &x.IsBanned, &x.BannedReason, &x.BannedUntil, &x.Theme)
                out = append(out, x)
        }
        c.JSON(http.StatusOK, gin.H{"users": out, "page": page, "per_page": per})
}

func AdminDeleteUserHandler(c *gin.Context) {
        id := c.Param("id")
        _, err := DB.Exec(ctxBackground(), `DELETE FROM users WHERE id=$1`, id)
        if err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        c.JSON(http.StatusOK, gin.H{"ok": true})
}

type adminUserPatch struct {
        IsBanned     *bool   `json:"is_banned"`
        BannedReason *string `json:"banned_reason"`
        BannedUntil  *string `json:"banned_until"`
        Theme        *string `json:"theme"`
}

func AdminPatchUserHandler(c *gin.Context) {
        id := c.Param("id")
        var req adminUserPatch
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        var bannedUntil any
        if req.BannedUntil != nil {
                if t, err := time.Parse(time.RFC3339, *req.BannedUntil); err == nil {
                        bannedUntil = t
                }
        }
        _, err := DB.Exec(ctxBackground(), `
                UPDATE users SET
                  is_banned=COALESCE($2, is_banned),
                  banned_reason=COALESCE($3, banned_reason),
                  banned_until=COALESCE($4, banned_until),
                  theme=COALESCE($5, theme)
                WHERE id=$1`, id, req.IsBanned, req.BannedReason, bannedUntil, req.Theme)
        if err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ============================ Settings ============================

func AdminGetSettingsHandler(c *gin.Context) {
        rows, err := DB.Query(ctxBackground(), `SELECT key, value FROM settings ORDER BY key`)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        m := map[string]string{}
        for rows.Next() {
                var k, v string
                _ = rows.Scan(&k, &v)
                m[k] = v
        }
        c.JSON(http.StatusOK, gin.H{"settings": m})
}

func AdminPutSettingsHandler(c *gin.Context) {
        var body map[string]string
        if err := c.ShouldBindJSON(&body); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        for k, v := range body {
                _, err := DB.Exec(ctxBackground(),
                        `INSERT INTO settings (key, value, updated_at) VALUES ($1,$2,now())
                         ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=now()`, k, v)
                if err != nil {
                        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "key": k})
                        return
                }
        }
        c.JSON(http.StatusOK, gin.H{"ok": true, "updated": len(body)})
}

// ============================ Admin messaging ============================
//
// Admin sees messages addressed to admin (to_user_id IS NULL). Admin replies
// are inserted as from_user_id IS NULL, to_user_id = <user>.

func AdminListConversationsHandler(c *gin.Context) {
        rows, err := DB.Query(ctxBackground(), `
                SELECT m.from_user_id::text, u.username,
                       (SELECT body FROM messages m2
                         WHERE ((m2.from_user_id = m.from_user_id AND m2.to_user_id IS NULL)
                            OR (m2.to_user_id = m.from_user_id AND m2.from_user_id IS NULL))
                         ORDER BY m2.created_at DESC LIMIT 1) AS last_body,
                       (SELECT created_at FROM messages m2
                         WHERE ((m2.from_user_id = m.from_user_id AND m2.to_user_id IS NULL)
                            OR (m2.to_user_id = m.from_user_id AND m2.from_user_id IS NULL))
                         ORDER BY m2.created_at DESC LIMIT 1) AS last_at,
                       (SELECT COUNT(*) FROM messages m3
                         WHERE m3.to_user_id IS NULL AND m3.from_user_id = m.from_user_id AND m3.is_read = FALSE) AS unread
                FROM messages m
                JOIN users u ON u.id = m.from_user_id
                WHERE m.to_user_id IS NULL
                GROUP BY m.from_user_id, u.username
                ORDER BY last_at DESC NULLS LAST`)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        type convo struct {
                UserID   string    `json:"user_id"`
                Username string    `json:"username"`
                LastBody string    `json:"last_body"`
                LastAt   time.Time `json:"last_at"`
                Unread   int       `json:"unread"`
        }
        out := []convo{}
        for rows.Next() {
                var x convo
                _ = rows.Scan(&x.UserID, &x.Username, &x.LastBody, &x.LastAt, &x.Unread)
                out = append(out, x)
        }
        c.JSON(http.StatusOK, gin.H{"conversations": out})
}

func AdminGetUserMessagesHandler(c *gin.Context) {
        userID := c.Param("user_id")
        if !validateUUID(userID) {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
                return
        }
        rows, err := DB.Query(ctxBackground(), `
                SELECT m.id, m.from_user_id, COALESCE(u.username, ''), m.to_user_id, '', m.body, m.created_at, m.is_read
                FROM messages m
                LEFT JOIN users u ON u.id = m.from_user_id
                WHERE (m.from_user_id::text = $1 AND m.to_user_id IS NULL)
                   OR (m.to_user_id::text = $1 AND m.from_user_id IS NULL)
                ORDER BY m.created_at ASC`, userID)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        out := []messageDTO{}
        for rows.Next() {
                var m messageDTO
                _ = rows.Scan(&m.ID, &m.FromUserID, &m.FromName, &m.ToUserID, &m.ToName, &m.Body, &m.CreatedAt, &m.IsRead)
                out = append(out, m)
        }
        // Mark as read the messages the user sent to admin.
        _, _ = DB.Exec(ctxBackground(),
                `UPDATE messages SET is_read=TRUE WHERE from_user_id::text=$1 AND to_user_id IS NULL`, userID)
        c.JSON(http.StatusOK, gin.H{"messages": out})
}

type adminReply struct {
        Body string `json:"body" binding:"required,max=8000"`
}

func AdminReplyToUserHandler(c *gin.Context) {
        userID := c.Param("user_id")
        if !validateUUID(userID) {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
                return
        }
        var req adminReply
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        id := uuid.NewString()
        _, err := DB.Exec(ctxBackground(),
                `INSERT INTO messages (id, from_user_id, to_user_id, body) VALUES ($1, NULL, $2::uuid, $3)`,
                id, userID, req.Body)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        c.JSON(http.StatusCreated, gin.H{"id": id, "body": req.Body, "created_at": time.Now().UTC()})
}

// public settings endpoint (no admin) for the frontend to read theme + pow difficulties
func PublicSettingsHandler(c *gin.Context) {
        rows, err := DB.Query(ctxBackground(), `SELECT key, value FROM settings`)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        m := map[string]string{}
        for rows.Next() {
                var k, v string
                _ = rows.Scan(&k, &v)
                m[k] = v
        }
        // Convert known int fields to int for convenience
        out := map[string]any{}
        for k, v := range m {
                if n, err := strconv.Atoi(v); err == nil {
                        out[k] = n
                } else {
                        out[k] = v
                }
        }
        c.JSON(http.StatusOK, out)
}
