package nexus

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// APIVersion identifies which version of the Nexus API a client speaks. The
// two versions differ only in how requests are authenticated: v2 signs with a
// symmetric HMAC secret shared with the server, v3 with a per-client Ed25519
// private key the server verifies against the matching public key.
type APIVersion string

const (
	// APIV2 is the legacy API, authenticated with a shared HMAC-SHA512 secret.
	APIV2 APIVersion = "v2"
	// APIV3 is the public-key API, authenticated with an Ed25519 signature.
	APIV3 APIVersion = "v3"
)

// Algorithm names as written by nexus-generate-key, which encodes keys as
// "<algorithm>:<base64>".
const (
	hmacAlgorithm    = "HmacSHA512"
	ed25519Algorithm = "Ed25519"
)

// Signer produces the Access-Signature header value for a canonical request
// string, and reports which API version its signatures are valid for.
type Signer interface {
	// Sign returns the base64-encoded signature of content.
	Sign(content string) (string, error)
	// APIVersion reports the API version this signer authenticates against.
	APIVersion() APIVersion
}

type hmacSigner struct {
	key []byte
}

// NewHMACSigner returns a Signer that authenticates against the legacy
// HMAC-SHA512 /api/v2 API using the given shared secret.
func NewHMACSigner(key []byte) Signer {
	return &hmacSigner{key: key}
}

func (s *hmacSigner) Sign(content string) (string, error) {
	h := hmac.New(sha512.New, s.key)
	h.Write([]byte(content))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func (s *hmacSigner) APIVersion() APIVersion { return APIV2 }

type ed25519Signer struct {
	key ed25519.PrivateKey
}

// NewEd25519Signer returns a Signer that authenticates against the public-key
// /api/v3 API using the given Ed25519 private key.
func NewEd25519Signer(key ed25519.PrivateKey) Signer {
	return &ed25519Signer{key: key}
}

func (s *ed25519Signer) Sign(content string) (string, error) {
	// The server verifies with java.security.Signature("Ed25519") over the
	// UTF-8 bytes of the same canonical string, and both sides produce the
	// raw 64-byte R||S signature, so no further framing is involved.
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, []byte(content))), nil
}

func (s *ed25519Signer) APIVersion() APIVersion { return APIV3 }

// ParseKey builds a Signer from a key as stored on disk or in a Kubernetes
// secret, choosing the API version from the key's own algorithm tag.
//
// It accepts the "<algorithm>:<base64>" form written by nexus-generate-key --
// "Ed25519:<base64 PKCS#8>" for a v3 private key, "HmacSHA512:<base64>" for a
// v2 secret -- as well as a bare base64 HMAC secret with no algorithm tag,
// which is how challenge secrets were stored before v3 existed.
func ParseKey(encoded string) (Signer, error) {
	algorithm, material, tagged := splitKey(encoded)
	if !tagged {
		// Untagged: a bare base64 HMAC secret, the pre-v3 format.
		key, err := base64.StdEncoding.DecodeString(material)
		if err != nil {
			return nil, fmt.Errorf("key is neither \"<algorithm>:<base64>\" nor bare base64: %w", err)
		}
		return NewHMACSigner(key), nil
	}

	switch algorithm {
	case ed25519Algorithm:
		return parseEd25519Key(material)
	case hmacAlgorithm:
		key, err := base64.StdEncoding.DecodeString(material)
		if err != nil {
			return nil, fmt.Errorf("error decoding %v key: %w", algorithm, err)
		}
		return NewHMACSigner(key), nil
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q: expected %v (public-key /api/v3) or %v (legacy /api/v2)",
			algorithm, ed25519Algorithm, hmacAlgorithm)
	}
}

// ParseEd25519Key builds a v3 Signer, rejecting anything that is not an
// Ed25519 private key. Use it where the caller has said which kind of key it
// is passing, so a key/setting mismatch fails with a clear message instead of
// silently authenticating against the wrong API version.
func ParseEd25519Key(encoded string) (Signer, error) {
	algorithm, material, tagged := splitKey(encoded)
	if tagged && algorithm != ed25519Algorithm {
		return nil, fmt.Errorf("key is %v, not %v -- an HMAC secret belongs in the legacy API-key setting, not the private-key setting",
			algorithm, ed25519Algorithm)
	}
	return parseEd25519Key(material)
}

// ParseHMACKey builds a v2 Signer, rejecting an Ed25519 private key with a
// clear message rather than treating its bytes as an HMAC secret -- which
// would otherwise fail much later, as an unexplained 401 from the server.
func ParseHMACKey(encoded string) (Signer, error) {
	algorithm, material, tagged := splitKey(encoded)
	if tagged && algorithm == ed25519Algorithm {
		return nil, fmt.Errorf("key is %v (a private key for the public-key /api/v3 API), not an HMAC secret -- pass it via the private-key setting",
			algorithm)
	}
	if tagged && algorithm != hmacAlgorithm {
		return nil, fmt.Errorf("unsupported HMAC key algorithm %q: expected %v", algorithm, hmacAlgorithm)
	}
	key, err := base64.StdEncoding.DecodeString(material)
	if err != nil {
		return nil, fmt.Errorf("error decoding HMAC key: %w", err)
	}
	return NewHMACSigner(key), nil
}

func parseEd25519Key(material string) (Signer, error) {
	der, err := base64.StdEncoding.DecodeString(material)
	if err != nil {
		return nil, fmt.Errorf("error decoding %v key: %w", ed25519Algorithm, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("error parsing %v private key: %w", ed25519Algorithm, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is a %T, not an %v private key", parsed, ed25519Algorithm)
	}
	return NewEd25519Signer(key), nil
}

// splitKey separates the "<algorithm>:<base64>" form into its parts. tagged
// reports whether an algorithm tag was present; when it is not, material is
// the whole (trimmed) input.
func splitKey(encoded string) (algorithm, material string, tagged bool) {
	trimmed := strings.TrimSpace(encoded)
	algorithm, material, tagged = strings.Cut(trimmed, ":")
	if !tagged {
		return "", trimmed, false
	}
	return algorithm, strings.TrimSpace(material), true
}
