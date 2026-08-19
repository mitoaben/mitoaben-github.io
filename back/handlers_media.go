package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// UploadAttachmentsHandler accepts multipart uploads for a post.
// POST /api/posts/:id/attachments  (auth required; user must own the post)
//
// We enforce:
//   - MaxAttachments per post (counting existing)
//   - MaxUploadBytes per file
//   - ALLOWED_MIME whitelist
//
// Files are stored at uploads_dir/YYYY/MM/DD/randomhex.ext  (sharded by date to keep
// directories small).  The DB row in attachments(id, post_id, file_path, file_name,
// mime_type, file_size) is created atomically.
func UploadAttachmentsHandler(c *gin.Context) {
	postID := c.Param("id")
	if !validateUUID(postID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid post id"})
		return
	}
	uid, _ := c.Get("user_id")
	// Verify ownership of the post
	var owner string
	err := DB.QueryRow(ctxBackground(), `SELECT user_id FROM posts WHERE id=$1`, postID).Scan(&owner)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "post not found"})
		return
	}
	if owner != uid {
		c.JSON(http.StatusForbidden, gin.H{"error": "not post owner"})
		return
	}
	// count existing
	var existing int
	_ = DB.QueryRow(ctxBackground(), `SELECT COUNT(*) FROM attachments WHERE post_id=$1`, postID).Scan(&existing)
	if existing >= AppConfig.MaxAttachments {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("max %d attachments reached", AppConfig.MaxAttachments)})
		return
	}

	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart form expected: " + err.Error()})
		return
	}
	files := form.File["files"]
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no files uploaded"})
		return
	}
	if existing+len(files) > AppConfig.MaxAttachments {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("would exceed max %d attachments", AppConfig.MaxAttachments)})
		return
	}

	allowedMime := map[string]bool{}
	for _, m := range AppConfig.AllowedMimes {
		allowedMime[strings.TrimSpace(m)] = true
	}

	uploaded := []attachmentDTO{}
	for _, fh := range files {
		if fh.Size > AppConfig.MaxUploadBytes {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("file %s exceeds max upload size", fh.Filename)})
			return
		}
		// Determine MIME from extension (defensive: also check header via DetectContentType)
		ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(fh.Filename), "."))
		mime := extToMime(ext)
		if !allowedMime[mime] {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("file type %s (%s) not allowed", fh.Filename, mime)})
			return
		}
		// Save file to disk: uploads_dir/YYYY/MM/DD/randomhex.ext
		now := nowDateParts()
		dir := filepath.Join(AppConfig.UploadsDir, now.y, now.m, now.d)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "mkdir failed"})
			return
		}
		randBuf := make([]byte, 16)
		if _, err := rand.Read(randBuf); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "rand failed"})
			return
		}
		filename := hex.EncodeToString(randBuf)
		if ext != "" {
			filename += "." + ext
		}
		fullPath := filepath.Join(dir, filename)
		src, err := fh.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "file open failed"})
			return
		}
		dst, err := os.Create(fullPath)
		if err != nil {
			src.Close()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
			return
		}
		// Detect content-type from first 512 bytes
		buf := make([]byte, 0, 512)
		// read at most 512 bytes for sniff
		headBuf := make([]byte, 512)
		n, _ := src.Read(headBuf)
		buf = headBuf[:n]
		sniffed := http.DetectContentType(buf)
		// write head first then the rest
		if _, err := dst.Write(buf); err != nil {
			src.Close()
			dst.Close()
			os.Remove(fullPath)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "write failed"})
			return
		}
		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			os.Remove(fullPath)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "copy failed"})
			return
		}
		src.Close()
		dst.Close()

		// Re-validate sniffed MIME if it's an image/video; PDF/text may sniff as text/plain or application/octet-stream
		if !isAllowedSniffed(sniffed, allowedMime, mime) {
			os.Remove(fullPath)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("file %s content does not match extension", fh.Filename)})
			return
		}
		aid := uuid.NewString()
		_, err = DB.Exec(ctxBackground(),
			`INSERT INTO attachments (id, post_id, file_path, file_name, mime_type, file_size) VALUES ($1, $2, $3, $4, $5, $6)`,
			aid, postID, fullPath, fh.Filename, mime, fh.Size)
		if err != nil {
			os.Remove(fullPath)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "attachment insert failed: " + err.Error()})
			return
		}
		uploaded = append(uploaded, attachmentDTO{
			ID:       aid,
			FileName: fh.Filename,
			MimeType: mime,
			FileSize: fh.Size,
			URL:      "/api/files/" + aid,
		})
	}
	c.JSON(http.StatusCreated, gin.H{"attachments": uploaded})
}

// GetFileHandler streams a stored attachment.
// GET /api/files/:id
func GetFileHandler(c *gin.Context) {
	id := c.Param("id")
	if !validateUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var path, mime, name string
	err := DB.QueryRow(ctxBackground(),
		`SELECT file_path, mime_type, file_name FROM attachments WHERE id=$1`, id).
		Scan(&path, &mime, &name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}
	f, err := os.Open(path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file missing on disk"})
		return
	}
	defer f.Close()
	c.Header("Content-Type", mime)
	c.Header("Content-Disposition", fmt.Sprintf("inline; filename=%q", name))
	c.File(path)
}

// DeleteAttachmentHandler deletes an attachment (owner or admin only).
// DELETE /api/posts/:id/attachments/:aid
func DeleteAttachmentHandler(c *gin.Context) {
	postID := c.Param("id")
	aid := c.Param("aid")
	uid, _ := c.Get("user_id")
	_, isAdmin := c.Get("admin_token")
	var path string
	var owner string
	err := DB.QueryRow(ctxBackground(),
		`SELECT a.file_path, p.user_id FROM attachments a JOIN posts p ON p.id = a.post_id WHERE a.id=$1 AND a.post_id=$2`,
		aid, postID).Scan(&path, &owner)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "attachment not found"})
		return
	}
	if owner != uid && !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "not allowed"})
		return
	}
	_, err = DB.Exec(ctxBackground(), `DELETE FROM attachments WHERE id=$1`, aid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	_ = os.Remove(path)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// extToMime maps common file extensions to MIME types.
func extToMime(ext string) string {
	switch ext {
	case "jpg", "jpeg":
		return "image/jpeg"
	case "png":
		return "image/png"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	case "mp4":
		return "video/mp4"
	case "webm":
		return "video/webm"
	case "pdf":
		return "application/pdf"
	case "txt":
		return "text/plain"
	case "mov":
		return "video/quicktime"
	case "svg":
		return "image/svg+xml"
	}
	return "application/octet-stream"
}

// isAllowedSniffed ensures the sniffed content type matches an allowed mime, with sane
// tolerance for variants like "image/jpeg; charset=binary" and PDF octet-streams.
func isAllowedSniffed(sniffed string, allowed map[string]bool, declared string) bool {
	sniffed = strings.SplitN(sniffed, ";", 2)[0]
	sniffed = strings.TrimSpace(sniffed)
	if allowed[sniffed] {
		return true
	}
	if sniffed == "application/octet-stream" && (declared == "application/pdf" || strings.HasPrefix(declared, "video/")) {
		return true
	}
	if sniffed == "text/plain" && declared == "text/plain" {
		return true
	}
	return false
}

type dateParts struct{ y, m, d string }

func nowDateParts() dateParts {
	t := timeNowUTC()
	return dateParts{
		y: fmt.Sprintf("%04d", t.Year()),
		m: fmt.Sprintf("%02d", int(t.Month())),
		d: fmt.Sprintf("%02d", t.Day()),
	}
}
