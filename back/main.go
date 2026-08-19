package main

import (
        "fmt"
        "log"
        "net/http"
        "os"
        "os/signal"
        "syscall"
        "time"

        "github.com/gin-gonic/gin"
)

// AppConfig is the global configuration instance.
var AppConfig *Config

func main() {
        AppConfig = LoadConfig()
        log.Printf("[info] libtd.com backend starting on port %d", AppConfig.ServerPort)

        // Ensure uploads dir exists
        if err := os.MkdirAll(AppConfig.UploadsDir, 0o755); err != nil {
                log.Fatalf("[fatal] uploads dir: %v", err)
        }

        InitDB(AppConfig)

        gin.SetMode(gin.ReleaseMode)
        r := gin.New()
        r.Use(gin.Logger(), gin.Recovery(), CORSMiddleware())

        // Static files
        r.Static("/static", AppConfig.UploadsDir)

        // Public endpoints
        r.GET("/api/health", func(c *gin.Context) {
                c.JSON(http.StatusOK, gin.H{"ok": true, "ts": time.Now().UTC(), "service": "libtd.com"})
        })
        r.GET("/api/settings", PublicSettingsHandler)
        r.GET("/api/threads", ListThreadsHandler)
        r.GET("/api/threads/:slug", GetThreadHandler)
        r.GET("/api/threads/:slug/posts", ListPostsHandler)
        r.GET("/api/posts/:id/tree", GetPostTreeHandler)
        r.GET("/api/search", SearchPostsHandler)
        r.GET("/api/hashtags", PopularHashtagsHandler)
        r.GET("/api/hashtags/:tag", PostsByHashtagHandler)
        r.GET("/api/files/:id", GetFileHandler)

        // Auth (no auth middleware required)
        auth := r.Group("/api/auth")
        {
                auth.GET("/register/challenge", RegisterChallengeHandler)
                auth.POST("/register", RegisterHandler)
                auth.GET("/login/challenge", LoginChallengeHandler)
                auth.POST("/login", LoginHandler)
                auth.POST("/logout", LogoutHandler)
                auth.GET("/me", AuthMiddleware(), MeHandler)
        }

        // User-scoped endpoints (require auth)
        user := r.Group("/api", AuthMiddleware())
        {
                // PoW challenge endpoints for authenticated actions
                user.GET("/pow/challenge", func(c *gin.Context) {
                        purpose := c.Query("purpose")
                        // payloadHint: just use user_id + body hash for binding; client will recompute
                        hint := c.Query("hint")
                        // override hint if not provided to enforce binding to action context
                        if hint == "" {
                                if v, ok := c.Get("user_id"); ok {
                                        if s, ok2 := v.(string); ok2 {
                                                hint = s
                                        }
                                }
                        }
                        ch, err := IssueChallenge(PoWPurpose(purpose), fmt.Sprintf("%v", hint))
                        if err != nil {
                                c.JSON(http.StatusInternalServerError, gin.H{"error": "challenge failed"})
                                return
                        }
                        c.JSON(http.StatusOK, ch)
                })

                user.POST("/threads/:slug/posts", CreatePostHandler)
                user.POST("/posts/:id/replies", CreateReplyHandler)
                user.POST("/posts/:id/attachments", UploadAttachmentsHandler)
                user.DELETE("/posts/:id/attachments/:aid", DeleteAttachmentHandler)

                // Messages
                user.GET("/messages/conversations", ListConversationsHandler)
                user.GET("/messages/with/:partner", GetConversationHandler)
                user.GET("/messages/challenge", SendMessageChallengeHandler)
                user.POST("/messages/send", SendMessageHandler)

                // User search (for finding a conversation partner by username)
                user.GET("/users/search", UserSearchHandler)
        }

        // Admin auth (separate from user auth)
        r.POST("/api/admin/login", AdminLoginHandler)
        r.POST("/api/admin/logout", AdminAuthMiddleware(), AdminLogoutHandler)

        admin := r.Group("/api/admin", AdminAuthMiddleware())
        {
                admin.GET("/threads", AdminListThreadsHandler)
                admin.POST("/threads", AdminCreateThreadHandler)
                admin.PATCH("/threads/:id", AdminUpdateThreadHandler)
                admin.DELETE("/threads/:id", AdminDeleteThreadHandler)

                admin.GET("/users", AdminListUsersHandler)
                admin.DELETE("/users/:id", AdminDeleteUserHandler)
                admin.PATCH("/users/:id", AdminPatchUserHandler)

                admin.GET("/settings", AdminGetSettingsHandler)
                admin.PUT("/settings", AdminPutSettingsHandler)

                admin.GET("/messages", AdminListConversationsHandler)
                admin.GET("/messages/:user_id", AdminGetUserMessagesHandler)
                admin.POST("/messages/:user_id", AdminReplyToUserHandler)
        }

        addr := fmt.Sprintf(":%d", AppConfig.ServerPort)
        srv := &http.Server{
                Addr:              addr,
                Handler:           r,
                ReadHeaderTimeout: 10 * time.Second,
        }
        go func() {
                if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
                        log.Fatalf("[fatal] server: %v", err)
                }
        }()
        log.Printf("[info] HTTP server listening on http://localhost%s", addr)

        // Graceful shutdown on SIGINT/SIGTERM
        quit := make(chan os.Signal, 1)
        signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
        <-quit
        log.Printf("[info] shutting down...")
        _ = srv.Close()
        DB.Close()
        log.Printf("[info] bye")
}
