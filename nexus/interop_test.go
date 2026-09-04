package nexus

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

// Golden vectors produced by the JVM, using exactly the calls nexus.crypto
// makes: KeyPairGenerator("Ed25519") for the keypair, getEncoded() for the
// PKCS#8 private and X.509 public encodings, and Signature("Ed25519") over the
// UTF-8 bytes of the message. They pin the wire contract between this client
// and the Clojure server: if either side's encoding or signature framing ever
// drifts, these tests fail here rather than as an unexplained 401 in
// production.
const (
	jvmPrivateKey = "Ed25519:MC4CAQAwBQYDK2VwBCIEIIThN1plNzcX15LIi5Ah7VH7egfN0d30RtVTYkrq2jnp"
	jvmPublicKey  = "Ed25519:MCowBQYDK2VwAyEA/JLr1O13WlLcMs+8bzT3ZP0mNPExLj9UbDdRfepHuFk="
	jvmMessage    = `PUT/api/v3/domain/example.com/challenge/abc1700000000{"host":"h"}`
	jvmSignature  = "Vr+GKKfAOhFE1aYsaItVTsVTFFpzAuOJmYeexrjvMpdykDlY+RRm6NIOrOg7aeVeGMSzepC4fk38tydSqdL6Cw=="
)

// A private key written by nexus-generate-key --keypair must load here, and
// Ed25519 being deterministic, must produce the very same signature bytes the
// JVM produced for the same message.
func TestSignatureMatchesJVMGoldenVector(t *testing.T) {
	signer, err := ParseKey(jvmPrivateKey)
	if err != nil {
		t.Fatalf("ParseKey on a JVM-generated private key: %v", err)
	}
	if signer.APIVersion() != APIV3 {
		t.Errorf("APIVersion = %v, want %v", signer.APIVersion(), APIV3)
	}

	sig, err := signer.Sign(jvmMessage)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if sig != jvmSignature {
		t.Errorf("signature = %q, want the JVM's %q", sig, jvmSignature)
	}
}

// The server verifies against the X.509-encoded public key from the same
// keypair, so a signature this client produces must verify under it.
func TestSignatureVerifiesUnderJVMPublicKey(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(jvmPublicKey, "Ed25519:"))
	if err != nil {
		t.Fatalf("decoding the JVM public key: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("parsing the JVM public key: %v", err)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("JVM public key parsed as %T, want ed25519.PublicKey", parsed)
	}

	signer, err := ParseKey(jvmPrivateKey)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	sig, err := signer.Sign(jvmMessage)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if !ed25519.Verify(public, []byte(jvmMessage), raw) {
		t.Error("signature does not verify under the JVM-generated public key")
	}
}
