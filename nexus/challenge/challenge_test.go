package challenge

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fudoniten/nexus-go/nexus"
	"github.com/google/uuid"
)

// capturedRequest records what the fake Nexus server saw, so a test can check
// the path, headers and signature the client produced.
type capturedRequest struct {
	method    string
	path      string
	service   string
	signature string
	timestamp string
	body      string
}

// newTestClient stands up a TLS server that records one request and answers
// with status, and returns a NexusClient pointed at it.
func newTestClient(t *testing.T, signer nexus.Signer, status int) (*nexus.NexusClient, *capturedRequest) {
	t.Helper()

	captured := &capturedRequest{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.service = r.Header.Get("Service")
		captured.signature = r.Header.Get("Access-Signature")
		captured.timestamp = r.Header.Get("Access-Timestamp")
		captured.body = string(body)
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)

	return &nexus.NexusClient{
		Server:  strings.TrimPrefix(server.URL, "https://"),
		Domain:  "example.com",
		Service: "test-service",
		Signer:  signer,
		Client:  server.Client(),
	}, captured
}

// signedString reconstructs the canonical request string the server will
// verify: METHOD + path + timestamp + body.
func (c *capturedRequest) signedString() string {
	return fmt.Sprintf("%v%v%v%v", c.method, c.path, c.timestamp, c.body)
}

func hmacSignature(key []byte, content string) string {
	h := hmac.New(sha512.New, key)
	h.Write([]byte(content))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func TestCreateChallengeRecordV2(t *testing.T) {
	key := []byte("shared-hmac-secret")
	client, captured := newTestClient(t, nexus.NewHMACSigner(key), http.StatusOK)

	challengeID, err := CreateChallengeRecord(client, "host0", "challenge-secret")
	if err != nil {
		t.Fatalf("CreateChallengeRecord returned error: %v", err)
	}
	if challengeID == uuid.Nil {
		t.Fatal("CreateChallengeRecord returned nil challenge ID")
	}

	wantPath := fmt.Sprintf("/api/v2/domain/example.com/challenge/%v", challengeID)
	if captured.path != wantPath {
		t.Errorf("request path = %q, want %q", captured.path, wantPath)
	}
	if captured.method != "PUT" {
		t.Errorf("request method = %q, want PUT", captured.method)
	}
	if captured.service != "test-service" {
		t.Errorf("Service header = %q, want test-service", captured.service)
	}
	if want := hmacSignature(key, captured.signedString()); captured.signature != want {
		t.Errorf("Access-Signature = %q, want %q", captured.signature, want)
	}
}

func TestCreateChallengeRecordV3(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	client, captured := newTestClient(t, nexus.NewEd25519Signer(private), http.StatusOK)

	challengeID, err := CreateChallengeRecord(client, "host0", "challenge-secret")
	if err != nil {
		t.Fatalf("CreateChallengeRecord returned error: %v", err)
	}

	wantPath := fmt.Sprintf("/api/v3/domain/example.com/challenge/%v", challengeID)
	if captured.path != wantPath {
		t.Errorf("request path = %q, want %q", captured.path, wantPath)
	}

	sig, err := base64.StdEncoding.DecodeString(captured.signature)
	if err != nil {
		t.Fatalf("Access-Signature is not base64: %v", err)
	}
	if !ed25519.Verify(public, []byte(captured.signedString()), sig) {
		t.Error("Access-Signature does not verify against the signing key's public key")
	}
}

func TestCreateChallengeRecordRejectsErrorStatus(t *testing.T) {
	client, _ := newTestClient(t, nexus.NewHMACSigner([]byte("key")), http.StatusUnauthorized)

	if _, err := CreateChallengeRecord(client, "host0", "secret"); err == nil {
		t.Error("CreateChallengeRecord succeeded on a 401 response, want error")
	}
}

func TestDeleteChallengeRecordV2(t *testing.T) {
	key := []byte("shared-hmac-secret")
	client, captured := newTestClient(t, nexus.NewHMACSigner(key), http.StatusOK)
	challengeID := uuid.New()

	if err := DeleteChallengeRecord(client, challengeID); err != nil {
		t.Fatalf("DeleteChallengeRecord returned error: %v", err)
	}

	wantPath := fmt.Sprintf("/api/v2/domain/example.com/challenge/%v", challengeID)
	if captured.path != wantPath {
		t.Errorf("request path = %q, want %q", captured.path, wantPath)
	}
	if captured.method != "DELETE" {
		t.Errorf("request method = %q, want DELETE", captured.method)
	}
	// A DELETE carries no body, so the signed string ends at the timestamp.
	if want := hmacSignature(key, captured.signedString()); captured.signature != want {
		t.Errorf("Access-Signature = %q, want %q", captured.signature, want)
	}
}

func TestDeleteChallengeRecordV3(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	client, captured := newTestClient(t, nexus.NewEd25519Signer(private), http.StatusOK)
	challengeID := uuid.New()

	if err := DeleteChallengeRecord(client, challengeID); err != nil {
		t.Fatalf("DeleteChallengeRecord returned error: %v", err)
	}

	wantPath := fmt.Sprintf("/api/v3/domain/example.com/challenge/%v", challengeID)
	if captured.path != wantPath {
		t.Errorf("request path = %q, want %q", captured.path, wantPath)
	}

	sig, err := base64.StdEncoding.DecodeString(captured.signature)
	if err != nil {
		t.Fatalf("Access-Signature is not base64: %v", err)
	}
	if !ed25519.Verify(public, []byte(captured.signedString()), sig) {
		t.Error("Access-Signature does not verify against the signing key's public key")
	}
}

func TestDeleteChallengeRecordRejectsErrorStatus(t *testing.T) {
	client, _ := newTestClient(t, nexus.NewHMACSigner([]byte("key")), http.StatusNotFound)

	if err := DeleteChallengeRecord(client, uuid.New()); err == nil {
		t.Error("DeleteChallengeRecord succeeded on a 404 response, want error")
	}
}
