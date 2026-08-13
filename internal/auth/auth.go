// Package auth handles the two secrets this server actually manages: session
// tokens (opaque, stored hashed, revocable) and login passwords (argon2id).
// Neither of these is the E2EE key material -- that never reaches this
// server in any form. See the client's src/main/sync-keys.js for that half.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrMalformedHash is returned by VerifyPassword when the stored hash isn't
// in the format HashPassword produces -- a corrupt row, not a wrong
// password, and worth telling apart in a log even though the caller
// ultimately just refuses the login either way.
var ErrMalformedHash = errors.New("malformed password hash")

/* ------------------------------------------------------------------ *
 * Session tokens
 *
 * The token itself is bearer-secret and exists only in the login/register
 * response and the client's own memory. What's stored server-side is its
 * SHA-256 hash: fast on purpose, because the token is 256 bits of random
 * data, not a guessable password -- there's nothing here for a slow hash to
 * protect against, and a fast hash is what lets a lookup by token stay a
 * single indexed query.
 * ------------------------------------------------------------------ */

const tokenBytes = 32

// NewToken returns a random bearer token, base64url-encoded.
func NewToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken is what gets stored and queried by; never the token itself.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

/* ------------------------------------------------------------------ *
 * Login passwords
 *
 * argon2id, current OWASP first choice for a from-scratch password hash.
 * The client's own passphrase-derived key (see sync-keys.js) uses scrypt
 * instead, matching an already-proven code path there -- there's no
 * consistency argument for matching that choice here, since this is
 * genuinely new code with no existing primitive to reuse.
 * ------------------------------------------------------------------ */

const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB, i.e. 64 MiB
	argonThreads = 2
	argonKeyLen  = 32
	saltBytes    = 16
)

// HashPassword returns a self-describing hash string in the common
// $argon2id$v=..$m=..,t=..,p=..$salt$hash form, so the parameters travel
// with the hash and can be raised later without stranding hashes written
// under the old cost.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword returns whether password matches encoded, re-deriving with
// the parameters and salt read back out of encoded rather than assuming
// today's constants -- a password hashed under a previous cost still
// verifies correctly after argonTime/argonMemory are raised.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrMalformedHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, ErrMalformedHash
	}

	var memory uint32
	var time_ uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time_, &threads); err != nil {
		return false, ErrMalformedHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrMalformedHash
	}

	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrMalformedHash
	}

	got := argon2.IDKey([]byte(password), salt, time_, memory, threads, uint32(len(want)))

	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
