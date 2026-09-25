package auth

import (
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestTokenRoundTrip(t *testing.T) {
	tok, err := GenerateToken("u1", "admin", "super_admin", "t1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseToken(tok)
	if err != nil {
		t.Fatalf("parse own token: %v", err)
	}
	if claims.Role != "super_admin" {
		t.Fatalf("role = %q", claims.Role)
	}
}

func TestTokenForgedWithOldPublicKeyIsRejected(t *testing.T) {
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{Username: "attacker", Role: "super_admin"})
	s, err := forged.SignedString([]byte("flowlens-secret-key-change-in-production"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseToken(s); err == nil {
		t.Fatal("token signed with the previously hard-coded key was accepted")
	}
}

func TestUnsignedTokenIsRejected(t *testing.T) {
	none := jwt.NewWithClaims(jwt.SigningMethodNone, Claims{Role: "super_admin"})
	s, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseToken(s); err == nil {
		t.Fatal("alg=none token was accepted")
	}
}

func TestSetJWTSecret(t *testing.T) {
	old := jwtSecret
	defer func() { jwtSecret = old }()

	if err := SetJWTSecret("short"); err == nil {
		t.Fatal("short secret accepted")
	}
	if err := SetJWTSecret(strings.Repeat("k", 32)); err != nil {
		t.Fatalf("valid secret rejected: %v", err)
	}
	tok, _ := GenerateToken("u1", "admin", "super_admin", "t1")
	jwtSecret = old
	if _, err := ParseToken(tok); err == nil {
		t.Fatal("token from a different secret was accepted")
	}
}
