package main

import (
        "context"
        "fmt"
        "net/http"
        "regexp"
        "sort"
        "strings"
        "time"

        "github.com/gin-gonic/gin"
        "github.com/google/uuid"
)

// ============================ Threads ============================

type threadDTO struct {
        ID          string `json:"id"`
        Slug        string `json:"slug"`
        Name        string `json:"name"`
        Description string `json:"description"`
        PostCount   int    `json:"post_count"`
        IsActive    bool   `json:"is_active"`
        SortOrder   int    `json:"sort_order"`
}

func ListThreadsHandler(c *gin.Context) {
        rows, err := DB.Query(ctxBackground(), `
                SELECT t.id, t.slug, t.name, t.description, t.is_active, t.sort_order,
                       COALESCE((SELECT COUNT(*) FROM posts p WHERE p.thread_id = t.id), 0) AS post_count
                FROM threads t
                ORDER BY t.sort_order ASC, t.created_at ASC`)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        out := []threadDTO{}
        for rows.Next() {
                var t threadDTO
                if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Description, &t.IsActive, &t.SortOrder, &t.PostCount); err == nil {
                        out = append(out, t)
                }
        }
        c.JSON(http.StatusOK, gin.H{"threads": out})
}

func GetThreadHandler(c *gin.Context) {
        slug := c.Param("slug")
        var t threadDTO
        err := DB.QueryRow(ctxBackground(), `
                SELECT t.id, t.slug, t.name, t.description, t.is_active, t.sort_order,
                       COALESCE((SELECT COUNT(*) FROM posts p WHERE p.thread_id = t.id), 0)
                FROM threads t WHERE t.slug = $1`, slug).
                Scan(&t.ID, &t.Slug, &t.Name, &t.Description, &t.IsActive, &t.SortOrder, &t.PostCount)
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{"error": "thread not found"})
                return
        }
        c.JSON(http.StatusOK, t)
}

// ============================ Posts ============================

type attachmentDTO struct {
        ID       string `json:"id"`
        FileName string `json:"file_name"`
        MimeType string `json:"mime_type"`
        FileSize int64  `json:"file_size"`
        URL      string `json:"url"`
}

type postDTO struct {
        ID           string  `json:"id"`
        ThreadID     string  `json:"thread_id"`
        UserID       string  `json:"user_id"`
        Username     string  `json:"username"`
        ParentPostID *string `json:"parent_post_id"`
        IsOP         bool    `json:"is_op"`
        Title        string  `json:"title"`
        Body         string  `json:"body"`
        CreatedAt    time.Time `json:"created_at"`
        Upvotes      int     `json:"upvotes"`
        ReplyCount   int     `json:"reply_count"`
        Hashtags     []string        `json:"hashtags"`
        Attachments  []attachmentDTO `json:"attachments"`
        Depth        int             `json:"depth,omitempty"`
}

var hashtagRe = regexp.MustCompile(`(?:^|\s)#([A-Za-z0-9_]{2,32})`)

func parseHashtags(body string) []string {
        matches := hashtagRe.FindAllStringSubmatch(body, -1)
        seen := map[string]bool{}
        out := []string{}
        for _, m := range matches {
                tag := strings.ToLower(m[1])
                if !seen[tag] {
                        seen[tag] = true
                        out = append(out, tag)
                }
        }
        return out
}

type createPostRequest struct {
        Title     string `json:"title"`
        Body      string `json:"body" binding:"required,max=10000"`
        Challenge string `json:"challenge" binding:"required"`
        Nonce     uint64 `json:"nonce"`
}

// CreatePostHandler creates an OP (opening post) in a thread. PoW purpose = "post".
func CreatePostHandler(c *gin.Context) {
        slug := c.Param("slug")
        uid, _ := c.Get("user_id")
        uname, _ := c.Get("username")
        var req createPostRequest
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        // Find the thread
        var threadID string
        err := DB.QueryRow(ctxBackground(), `SELECT id FROM threads WHERE slug=$1 AND is_active=TRUE`, slug).Scan(&threadID)
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{"error": "thread not found or inactive"})
                return
        }
        // PoW payload digest = body[:64] + thread_id
        payloadHint := PayloadDigest(req.Body + "|" + threadID)
        if err := VerifyPoW(req.Challenge, req.Nonce, payloadHint, PurposePost); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": "PoW invalid: " + err.Error()})
                return
        }
        // Insert post
        postID := uuid.NewString()
        _, err = DB.Exec(ctxBackground(),
                `INSERT INTO posts (id, thread_id, user_id, is_op, title, body) VALUES ($1, $2, $3, TRUE, $4, $5)`,
                postID, threadID, uid, req.Title, req.Body)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "post insert failed: " + err.Error()})
                return
        }
        saveHashtagsForPost(postID, req.Body)
        // Attachments are saved separately via /api/posts/:id/attachments AFTER post creation
        // (because we need the post id). Frontend uploads attachments, then sends the post body
        // along with the uploaded attachment IDs. We support a second flow here as well:
        // if multipart/form-data is sent, we attach the files to the post.
        c.JSON(http.StatusCreated, gin.H{
                "id":         postID,
                "thread_id":  threadID,
                "user_id":    uid,
                "username":   uname,
                "title":       req.Title,
                "body":        req.Body,
                "created_at": time.Now().UTC(),
        })
}

type createReplyRequest struct {
        Title     string `json:"title"`
        Body      string `json:"body" binding:"required,max=10000"`
        Challenge string `json:"challenge" binding:"required"`
        Nonce     uint64 `json:"nonce"`
}

// CreateReplyHandler creates a reply (parent_post_id != NULL). PoW purpose = "reply".
func CreateReplyHandler(c *gin.Context) {
        parentID := c.Param("id")
        uid, _ := c.Get("user_id")
        uname, _ := c.Get("username")
        if !validateUUID(parentID) {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid parent id"})
                return
        }
        var req createReplyRequest
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }
        var parentThreadID string
        err := DB.QueryRow(ctxBackground(), `SELECT thread_id FROM posts WHERE id=$1`, parentID).Scan(&parentThreadID)
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{"error": "parent post not found"})
                return
        }
        payloadHint := PayloadDigest(req.Body + "|" + parentID)
        if err := VerifyPoW(req.Challenge, req.Nonce, payloadHint, PurposeReply); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": "PoW invalid: " + err.Error()})
                return
        }
        postID := uuid.NewString()
        _, err = DB.Exec(ctxBackground(),
                `INSERT INTO posts (id, thread_id, user_id, parent_post_id, is_op, title, body) VALUES ($1, $2, $3, $4, FALSE, $5, $6)`,
                postID, parentThreadID, uid, parentID, req.Title, req.Body)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "reply insert failed: " + err.Error()})
                return
        }
        // Bump parent's reply_count
        _, _ = DB.Exec(ctxBackground(), `UPDATE posts SET reply_count = reply_count + 1 WHERE id=$1`, parentID)
        saveHashtagsForPost(postID, req.Body)
        c.JSON(http.StatusCreated, gin.H{
                "id":             postID,
                "thread_id":      parentThreadID,
                "parent_post_id": parentID,
                "user_id":        uid,
                "username":       uname,
                "title":          req.Title,
                "body":           req.Body,
                "created_at":     time.Now().UTC(),
        })
}

// saveHashtagsForPost inserts hashtag rows + post_hashtags links and bumps usage_count.
func saveHashtagsForPost(postID, body string) {
        tags := parseHashtags(body)
        if len(tags) == 0 {
                return
        }
        for _, tag := range tags {
                var hid string
                err := DB.QueryRow(ctxBackground(), `
                        INSERT INTO hashtags (tag) VALUES ($1)
                        ON CONFLICT (tag) DO UPDATE SET usage_count = hashtags.usage_count + 1
                        RETURNING id`, tag).Scan(&hid)
                if err != nil {
                        continue
                }
                _, _ = DB.Exec(ctxBackground(),
                        `INSERT INTO post_hashtags (post_id, hashtag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
                        postID, hid)
        }
}

// ListPostsHandler lists OPs in a thread with sorting & pagination.
// GET /api/threads/:slug/posts?sort=new|hot|top&page=1&per=20
func ListPostsHandler(c *gin.Context) {
        slug := c.Param("slug")
        sortBy := c.DefaultQuery("sort", "new")
        page := parseIntDefault(c.Query("page"), 1)
        perPage := parseIntDefault(c.Query("per"), 20)
        if perPage < 1 || perPage > 100 {
                perPage = 20
        }
        if page < 1 {
                page = 1
        }
        offset := (page - 1) * perPage

        order := "p.created_at DESC"
        switch sortBy {
        case "hot":
                order = "(p.upvotes * 2 + p.reply_count) DESC, p.created_at DESC"
        case "top":
                order = "p.upvotes DESC, p.created_at DESC"
        case "replies":
                order = "p.reply_count DESC, p.created_at DESC"
        case "old":
                order = "p.created_at ASC"
        }

        rows, err := DB.Query(ctxBackground(), fmt.Sprintf(`
                SELECT p.id, p.thread_id, p.user_id, u.username, p.parent_post_id, p.is_op, p.title, p.body, p.created_at, p.upvotes, p.reply_count
                FROM posts p
                JOIN users u ON u.id = p.user_id
                JOIN threads t ON t.id = p.thread_id
                WHERE t.slug = $1 AND p.is_op = TRUE
                ORDER BY %s
                LIMIT $2 OFFSET $3`, order), slug, perPage, offset)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        postIDs := []string{}
        posts := []postDTO{}
        for rows.Next() {
                var p postDTO
                if err := rows.Scan(&p.ID, &p.ThreadID, &p.UserID, &p.Username, &p.ParentPostID, &p.IsOP, &p.Title, &p.Body, &p.CreatedAt, &p.Upvotes, &p.ReplyCount); err == nil {
                        posts = append(posts, p)
                        postIDs = append(postIDs, p.ID)
                }
        }
        // Attach hashtags + attachments in batch
        posts = enrichPosts(posts, postIDs)
        // total count
        var total int
        _ = DB.QueryRow(ctxBackground(),
                `SELECT COUNT(*) FROM posts p JOIN threads t ON t.id = p.thread_id WHERE t.slug=$1 AND p.is_op=TRUE`, slug).Scan(&total)
        c.JSON(http.StatusOK, gin.H{
                "posts":    posts,
                "page":     page,
                "per_page": perPage,
                "total":    total,
                "sort":     sortBy,
        })
}

// GetPostTreeHandler returns a post and all of its replies in tree form.
// GET /api/posts/:id/tree
func GetPostTreeHandler(c *gin.Context) {
        postID := c.Param("id")
        if !validateUUID(postID) {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
                return
        }
        // Recursive query for OP + all descendants ordered depth-first by created_at.
        rows, err := DB.Query(ctxBackground(), `
                WITH RECURSIVE tree AS (
                        SELECT p.id, p.thread_id, p.user_id, u.username, p.parent_post_id, p.is_op, p.title, p.body, p.created_at, p.upvotes, p.reply_count, 0 AS depth
                        FROM posts p JOIN users u ON u.id = p.user_id
                        WHERE p.id = $1
                        UNION ALL
                        SELECT c.id, c.thread_id, c.user_id, u.username, c.parent_post_id, c.is_op, c.title, c.body, c.created_at, c.upvotes, c.reply_count, t.depth + 1
                        FROM posts c
                        JOIN users u ON u.id = c.user_id
                        JOIN tree t ON c.parent_post_id = t.id
                )
                SELECT * FROM tree ORDER BY (CASE WHEN depth=0 THEN 0 ELSE 1 END), created_at ASC`, postID)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        posts := []postDTO{}
        ids := []string{}
        for rows.Next() {
                var p postDTO
                if err := rows.Scan(&p.ID, &p.ThreadID, &p.UserID, &p.Username, &p.ParentPostID, &p.IsOP, &p.Title, &p.Body, &p.CreatedAt, &p.Upvotes, &p.ReplyCount, &p.Depth); err == nil {
                        posts = append(posts, p)
                        ids = append(ids, p.ID)
                }
        }
        posts = enrichPosts(posts, ids)
        c.JSON(http.StatusOK, gin.H{"tree": posts, "root_id": postID})
}

// enrichPosts fills in hashtags + attachments for a list of posts in 2 batched queries.
func enrichPosts(posts []postDTO, ids []string) []postDTO {
        if len(ids) == 0 {
                return posts
        }
        // hashtags
        rows, err := DB.Query(ctxBackground(), `
                SELECT ph.post_id, h.tag FROM post_hashtags ph
                JOIN hashtags h ON h.id = ph.hashtag_id
                WHERE ph.post_id = ANY($1)`, ids)
        if err == nil {
                for rows.Next() {
                        var pid, tag string
                        if err := rows.Scan(&pid, &tag); err == nil {
                                for i := range posts {
                                        if posts[i].ID == pid {
                                                posts[i].Hashtags = append(posts[i].Hashtags, tag)
                                        }
                                }
                        }
                }
                rows.Close()
        }
        // attachments
        rows2, err := DB.Query(ctxBackground(), `
                SELECT id, post_id, file_name, mime_type, file_size FROM attachments WHERE post_id = ANY($1)`, ids)
        if err == nil {
                for rows2.Next() {
                        var a attachmentDTO
                        var pid string
                        if err := rows2.Scan(&a.ID, &pid, &a.FileName, &a.MimeType, &a.FileSize); err == nil {
                                a.URL = "/api/files/" + a.ID
                                for i := range posts {
                                        if posts[i].ID == pid {
                                                posts[i].Attachments = append(posts[i].Attachments, a)
                                        }
                                }
                        }
                }
                rows2.Close()
        }
        return posts
}

// SearchPostsHandler searches posts by title/body. Uses ILIKE for simplicity + tsvector for ranking.
// GET /api/search?q=foo&page=1&per=20
func SearchPostsHandler(c *gin.Context) {
        q := strings.TrimSpace(c.Query("q"))
        if q == "" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "q required"})
                return
        }
        page := parseIntDefault(c.Query("page"), 1)
        perPage := parseIntDefault(c.Query("per"), 20)
        if perPage < 1 || perPage > 100 {
                perPage = 20
        }
        offset := (page - 1) * perPage
        pattern := "%" + strings.ToLower(q) + "%"
        rows, err := DB.Query(ctxBackground(), `
                SELECT p.id, p.thread_id, p.user_id, u.username, p.parent_post_id, p.is_op, p.title, p.body, p.created_at, p.upvotes, p.reply_count
                FROM posts p JOIN users u ON u.id = p.user_id
                WHERE LOWER(p.title) LIKE $1 OR LOWER(p.body) LIKE $1
                ORDER BY p.created_at DESC
                LIMIT $2 OFFSET $3`, pattern, perPage, offset)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        posts := []postDTO{}
        ids := []string{}
        for rows.Next() {
                var p postDTO
                if err := rows.Scan(&p.ID, &p.ThreadID, &p.UserID, &p.Username, &p.ParentPostID, &p.IsOP, &p.Title, &p.Body, &p.CreatedAt, &p.Upvotes, &p.ReplyCount); err == nil {
                        posts = append(posts, p)
                        ids = append(ids, p.ID)
                }
        }
        posts = enrichPosts(posts, ids)
        var total int
        _ = DB.QueryRow(ctxBackground(),
                `SELECT COUNT(*) FROM posts WHERE LOWER(title) LIKE $1 OR LOWER(body) LIKE $1`, pattern).Scan(&total)
        c.JSON(http.StatusOK, gin.H{"posts": posts, "page": page, "per_page": perPage, "total": total, "q": q})
}

// PostsByHashtagHandler returns posts tagged with a hashtag.
// GET /api/hashtags/:tag
func PostsByHashtagHandler(c *gin.Context) {
        tag := strings.ToLower(strings.TrimPrefix(c.Param("tag"), "#"))
        if tag == "" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "tag required"})
                return
        }
        page := parseIntDefault(c.Query("page"), 1)
        perPage := parseIntDefault(c.Query("per"), 20)
        offset := (page - 1) * perPage
        rows, err := DB.Query(ctxBackground(), `
                SELECT p.id, p.thread_id, p.user_id, u.username, p.parent_post_id, p.is_op, p.title, p.body, p.created_at, p.upvotes, p.reply_count
                FROM posts p
                JOIN users u ON u.id = p.user_id
                JOIN post_hashtags ph ON ph.post_id = p.id
                JOIN hashtags h ON h.id = ph.hashtag_id
                WHERE h.tag = $1
                ORDER BY p.created_at DESC
                LIMIT $2 OFFSET $3`, tag, perPage, offset)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        posts := []postDTO{}
        ids := []string{}
        for rows.Next() {
                var p postDTO
                if err := rows.Scan(&p.ID, &p.ThreadID, &p.UserID, &p.Username, &p.ParentPostID, &p.IsOP, &p.Title, &p.Body, &p.CreatedAt, &p.Upvotes, &p.ReplyCount); err == nil {
                        posts = append(posts, p)
                        ids = append(ids, p.ID)
                }
        }
        posts = enrichPosts(posts, ids)
        var total int
        _ = DB.QueryRow(ctxBackground(), `
                SELECT COUNT(*) FROM post_hashtags ph JOIN hashtags h ON h.id = ph.hashtag_id WHERE h.tag=$1`, tag).Scan(&total)
        c.JSON(http.StatusOK, gin.H{"posts": posts, "page": page, "per_page": perPage, "total": total, "tag": tag})
}

// PopularHashtagsHandler returns the top N hashtags by usage_count.
// GET /api/hashtags?limit=20
func PopularHashtagsHandler(c *gin.Context) {
        limit := parseIntDefault(c.Query("limit"), 20)
        if limit < 1 || limit > 100 {
                limit = 20
        }
        rows, err := DB.Query(ctxBackground(),
                `SELECT tag, usage_count FROM hashtags WHERE usage_count > 0 ORDER BY usage_count DESC, tag ASC LIMIT $1`, limit)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                return
        }
        defer rows.Close()
        type ht struct {
                Tag       string `json:"tag"`
                UsageCount int   `json:"usage_count"`
        }
        out := []ht{}
        for rows.Next() {
                var h ht
                _ = rows.Scan(&h.Tag, &h.UsageCount)
                out = append(out, h)
        }
        c.JSON(http.StatusOK, gin.H{"hashtags": out})
}

func parseIntDefault(s string, def int) int {
        if s == "" {
                return def
        }
        n := 0
        for _, ch := range s {
                if ch < '0' || ch > '9' {
                        return def
                }
                n = n*10 + int(ch-'0')
        }
        return n
}

// re-export sort usage to satisfy unused import warning if enabled
var _ = sort.Strings

// backgroundCtx is a tiny helper so we don't shadow context in places where ctxBackground()
// is more readable but stdlib context.Context is needed for type signatures.
func backgroundCtx() context.Context { return context.Background() }
