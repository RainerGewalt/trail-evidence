package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// SignatureAlg is the only signature algorithm defined for v1.
const SignatureAlg = "ed25519"

// KeyID derives the recommended key identifier from an Ed25519 public key:
// "ed25519:" followed by the first 16 hex characters of SHA-256(public key).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:8])
}

// Sign attaches an Ed25519 signature over the ASCII bytes of r.ChainHash.
// The record must already be sealed. keyID may be empty, in which case KeyID
// of the corresponding public key is used.
func Sign(r *Record, priv ed25519.PrivateKey, keyID string) error {
	if r == nil || r.ChainHash == "" {
		return fmt.Errorf("sign: record is not sealed")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("sign: invalid private key length %d", len(priv))
	}
	if keyID == "" {
		keyID = KeyID(priv.Public().(ed25519.PublicKey))
	}
	sig := ed25519.Sign(priv, []byte(r.ChainHash))
	r.Signature = &Signature{
		Alg:   SignatureAlg,
		KeyID: keyID,
		Sig:   base64.RawURLEncoding.EncodeToString(sig),
	}
	return nil
}

// VerifySignature checks sig over the ASCII bytes of chainHash.
func VerifySignature(pub ed25519.PublicKey, chainHash string, sig *Signature) error {
	if sig == nil {
		return fmt.Errorf("record carries no signature")
	}
	if sig.Alg != SignatureAlg {
		return fmt.Errorf("unsupported signature algorithm %q", sig.Alg)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length %d", len(pub))
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig.Sig)
	if err != nil {
		return fmt.Errorf("signature is not base64url without padding: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("signature has %d bytes, want %d", len(raw), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, []byte(chainHash), raw) {
		return fmt.Errorf("signature does not verify with key %s", KeyID(pub))
	}
	return nil
}

// ParsePublicKey accepts a 64-character hex string, or the path of a file
// that contains either such a hex string or a PEM "PUBLIC KEY" block (PKIX).
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if pub, err := parseHexKey(s); err == nil {
		return pub, nil
	}
	data, err := os.ReadFile(s)
	if err != nil {
		return nil, fmt.Errorf("public key: %q is neither a 64-character hex key nor a readable file", s)
	}
	text := strings.TrimSpace(string(data))
	if blk, _ := pem.Decode(data); blk != nil {
		key, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("public key: %w", err)
		}
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key: PEM block is not an Ed25519 key")
		}
		return pub, nil
	}
	pub, err := parseHexKey(text)
	if err != nil {
		return nil, fmt.Errorf("public key file %q: %w", s, err)
	}
	return pub, nil
}

func parseHexKey(s string) (ed25519.PublicKey, error) {
	if len(s) != ed25519.PublicKeySize*2 {
		return nil, fmt.Errorf("expected %d hex characters", ed25519.PublicKeySize*2)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(b), nil
}
