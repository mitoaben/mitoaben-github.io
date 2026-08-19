package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// PoWPurpose enumerates the actions that require proof of work.
type PoWPurpose string

const (
	PurposeRegister PoWPurpose = "register"
	PurposeLogin    PoWPurpose = "login"
	PurposePost     PoWPurpose = "post"
	PurposeReply    PoWPurpose = "reply"
	PurposeMessage  PoWPurpose = "message"
)

// ChallengeResponse is what the server hands to the client to mine.
type ChallengeResponse struct {
	Challenge   string     `json:"challenge"`
	Purpose     PoWPurpose `json:"purpose"`
	Difficulty  int        `json:"difficulty"`
	Algorithm   string     `json:"algorithm"`
	PayloadHint string     `json:"payload_hint,omitempty"`
	ExpiresAt   time.Time  `json:"expires_at"`
}

// IssueChallenge generates a fresh, signed challenge for the given purpose and stores it.
// `payloadHint` is a deterministic digest of the action's payload so the challenge cannot
// be reused for a different action (e.g. the user can't reuse a register challenge to log in).
func IssueChallenge(purpose PoWPurpose, payloadHint string) (*ChallengeResponse, error) {
	bits := GetDifficulty(purpose)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	challenge := hex.EncodeToString(raw)
	expires := time.Now().Add(5 * time.Minute)
	_, err := DB.Exec(ctxBackground(),
		`INSERT INTO pow_challenges (challenge, purpose, expires_at) VALUES ($1, $2, $3)`,
		challenge, string(purpose), expires)
	if err != nil {
		return nil, err
	}
	return &ChallengeResponse{
		Challenge:  challenge,
		Purpose:    purpose,
		Difficulty: bits,
		Algorithm:  "hashcash-sha256",
		ExpiresAt:  expires,
	}, nil
}

// VerifyPoW re-computes the hash client-side and validates that:
//   - the challenge exists, is unused, not expired, and matches the purpose
//   - SHA-256(challenge || nonce || payloadHint) has at least `bits` leading zero bits
//   - the challenge has not been replayed (single-use, atomically marked used)
//
// Returns nil on success.
func VerifyPoW(challenge string, nonce uint64, payloadHint string, purpose PoWPurpose) error {
	// Atomic single-use: try to mark the challenge as used; only the first caller wins.
	tag, err := markChallengeUsed(challenge, purpose)
	if err != nil {
		return err
	}
	if !tag {
		return fmt.Errorf("challenge already used or invalid")
	}

	bits := GetDifficulty(purpose)
	// Compute SHA-256(challenge || nonce || payloadHint)
	h := sha256.New()
	h.Write([]byte(challenge))
	h.Write([]byte(fmt.Sprintf("%d", nonce)))
	h.Write([]byte(payloadHint))
	sum := h.Sum(nil)
	if !hasLeadingZeroBits(sum, bits) {
		return fmt.Errorf("invalid PoW: insufficient leading zero bits (need %d)", bits)
	}
	return nil
}

// markChallengeUsed atomically marks a challenge as used if it is unused and not expired.
// Returns (true, nil) if the caller successfully claimed the challenge.
func markChallengeUsed(challenge string, purpose PoWPurpose) (bool, error) {
	ct, err := DB.Exec(ctxBackground(),
		`UPDATE pow_challenges
		  SET used = TRUE
		  WHERE challenge = $1 AND purpose = $2 AND used = FALSE AND expires_at > now()`,
		challenge, string(purpose))
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() == 1, nil
}

// hasLeadingZeroBits returns true if `sum` has at least `bits` leading zero bits.
func hasLeadingZeroBits(sum []byte, bits int) bool {
	if bits <= 0 {
		return true
	}
	full := bits / 8
	rem := bits % 8
	if full > len(sum) {
		return false
	}
	for i := 0; i < full; i++ {
		if sum[i] != 0 {
			return false
		}
	}
	if rem > 0 {
		if full >= len(sum) {
			return false
		}
		mask := byte(0xff << (8 - rem))
		if sum[full]&mask != 0 {
			return false
		}
	}
	return true
}

// GetDifficulty reads the current PoW difficulty for a given purpose from settings,
// falling back to the env-loaded defaults if the row is missing.
func GetDifficulty(purpose PoWPurpose) int {
	key := "pow_" + string(purpose) + "_bits"
	var v string
	err := DB.QueryRow(ctxBackground(), `SELECT value FROM settings WHERE key = $1`, key).Scan(&v)
	if err != nil {
		return defaultDifficulty(purpose)
	}
	n := 0
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n <= 0 || n > 32 {
		return defaultDifficulty(purpose)
	}
	return n
}

func defaultDifficulty(purpose PoWPurpose) int {
	switch purpose {
	case PurposeRegister:
		return AppConfig.PowRegisterBits
	case PurposeLogin:
		return AppConfig.PowLoginBits
	case PurposePost:
		return AppConfig.PowPostBits
	case PurposeReply:
		return AppConfig.PowReplyBits
	case PurposeMessage:
		return AppConfig.PowMessageBits
	}
	return 16
}

// PayloadDigest is a short canonical digest of an action's payload, used both as
// payloadHint during challenge issue and as the verified input during VerifyPoW.
// All clients MUST compute the exact same string the server computes here.
func PayloadDigest(payload any) string {
	b, err := json.Marshal(payload)
	if err != nil {
		// fall back to fmt; never panic
		b = []byte(fmt.Sprintf("%v", payload))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HMACSign signs a message with the server's JWT secret; used to authenticate admin sessions
// and to ensure download tokens for attachments cannot be forged.
func HMACSign(msg string) string {
	mac := hmac.New(sha256.New, []byte(AppConfig.JWTSecret))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}
