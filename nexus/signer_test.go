package nexus

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

// encodedEd25519Key renders a private key the way nexus-generate-key --keypair
// writes it: "Ed25519:" followed by base64 PKCS#8.
func encodedEd25519Key(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling private key: %v", err)
	}
	return "Ed25519:" + base64.StdEncoding.EncodeToString(der)
}

func TestParseKeyEd25519(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	signer, err := ParseKey(encodedEd25519Key(t, private))
	if err != nil {
		t.Fatalf("ParseKey returned error: %v", err)
	}
	if signer.APIVersion() != APIV3 {
		t.Errorf("APIVersion = %v, want %v", signer.APIVersion(), APIV3)
	}

	sig, err := signer.Sign("some canonical request")
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if !ed25519.Verify(public, []byte("some canonical request"), raw) {
		t.Error("signature does not verify against the matching public key")
	}
}

func TestParseKeyHMACTagged(t *testing.T) {
	signer, err := ParseKey("HmacSHA512:" + base64.StdEncoding.EncodeToString([]byte("secret")))
	if err != nil {
		t.Fatalf("ParseKey returned error: %v", err)
	}
	if signer.APIVersion() != APIV2 {
		t.Errorf("APIVersion = %v, want %v", signer.APIVersion(), APIV2)
	}
}

func TestParseKeyUntaggedIsHMAC(t *testing.T) {
	// The pre-v3 challenge secret format: bare base64, no algorithm tag.
	encoded := base64.StdEncoding.EncodeToString([]byte("secret"))

	signer, err := ParseKey(encoded)
	if err != nil {
		t.Fatalf("ParseKey returned error: %v", err)
	}
	if signer.APIVersion() != APIV2 {
		t.Errorf("APIVersion = %v, want %v", signer.APIVersion(), APIV2)
	}

	// An untagged secret must sign identically to the same bytes passed
	// directly, so migrating a caller to ParseKey cannot change signatures.
	direct, err := NewHMACSigner([]byte("secret")).Sign("content")
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	parsed, err := signer.Sign("content")
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if parsed != direct {
		t.Errorf("signature from parsed key = %q, want %q", parsed, direct)
	}
}

func TestParseKeyTrimsSurroundingWhitespace(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	// A key file read off disk, or out of a secret, often has a trailing
	// newline.
	if _, err := ParseKey("\n" + encodedEd25519Key(t, private) + "\n"); err != nil {
		t.Errorf("ParseKey returned error on a padded key: %v", err)
	}
}

func TestParseKeyRejectsUnknownAlgorithm(t *testing.T) {
	_, err := ParseKey("HmacSHA256:" + base64.StdEncoding.EncodeToString([]byte("secret")))
	if err == nil {
		t.Fatal("ParseKey accepted an unsupported algorithm, want error")
	}
	if !strings.Contains(err.Error(), "HmacSHA256") {
		t.Errorf("error %q does not name the offending algorithm", err)
	}
}

func TestParseEd25519KeyRejectsHMACKey(t *testing.T) {
	_, err := ParseEd25519Key("HmacSHA512:" + base64.StdEncoding.EncodeToString([]byte("secret")))
	if err == nil {
		t.Fatal("ParseEd25519Key accepted an HMAC key, want error")
	}
	if !strings.Contains(err.Error(), "HmacSHA512") {
		t.Errorf("error %q does not name the offending algorithm", err)
	}
}

func TestParseHMACKeyRejectsEd25519Key(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	_, err = ParseHMACKey(encodedEd25519Key(t, private))
	if err == nil {
		t.Fatal("ParseHMACKey accepted an Ed25519 private key, want error")
	}
	if !strings.Contains(err.Error(), "Ed25519") {
		t.Errorf("error %q does not name the offending algorithm", err)
	}
}

func TestParseHMACKeyAcceptsUntagged(t *testing.T) {
	if _, err := ParseHMACKey(base64.StdEncoding.EncodeToString([]byte("secret"))); err != nil {
		t.Errorf("ParseHMACKey rejected a bare base64 secret: %v", err)
	}
}

func TestParseEd25519KeyRejectsGarbage(t *testing.T) {
	if _, err := ParseEd25519Key("Ed25519:" + base64.StdEncoding.EncodeToString([]byte("not a key"))); err == nil {
		t.Error("ParseEd25519Key accepted non-PKCS#8 bytes, want error")
	}
}

func TestEndpointUsesSignerAPIVersion(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	for _, tc := range []struct {
		name   string
		signer Signer
		want   string
	}{
		{"hmac", NewHMACSigner([]byte("secret")), "/api/v2/domain/example.com/challenge/abc"},
		{"ed25519", NewEd25519Signer(private), "/api/v3/domain/example.com/challenge/abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &NexusClient{Signer: tc.signer}
			got := client.Endpoint("/domain/%v/challenge/%v", "example.com", "abc")
			if got != tc.want {
				t.Errorf("Endpoint = %q, want %q", got, tc.want)
			}
		})
	}
}
