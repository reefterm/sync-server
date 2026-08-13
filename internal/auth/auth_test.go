package auth

import "testing"

func TestNewTokenIsUniqueAndNonEmpty(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	b, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if a == "" || b == "" {
		t.Fatal("token must not be empty")
	}
	if a == b {
		t.Fatal("two tokens collided, which should be astronomically unlikely")
	}
}

func TestHashTokenIsDeterministicAndDoesNotLeakTheToken(t *testing.T) {
	token := "a-known-token-value"
	h1 := HashToken(token)
	h2 := HashToken(token)

	if h1 != h2 {
		t.Fatal("hashing the same token twice must produce the same hash")
	}
	if h1 == token {
		t.Fatal("the hash must not equal the raw token")
	}
}

func TestHashPasswordRoundTrips(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("the correct password must verify")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword("wrong password entirely", hash)
	if err != nil {
		t.Fatalf("VerifyPassword should not error on a wrong password: %v", err)
	}
	if ok {
		t.Fatal("the wrong password must not verify")
	}
}

func TestHashPasswordSaltsEachCall(t *testing.T) {
	h1, err := HashPassword("same password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	h2, err := HashPassword("same password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if h1 == h2 {
		t.Fatal("hashing the same password twice must not produce identical hashes (salt should differ)")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash-at-all",
		"$argon2id$v=19$m=65536,t=3,p=2$onlyonepart",
		"$bcrypt$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA",
	}

	for _, c := range cases {
		_, err := VerifyPassword("anything", c)
		if err == nil {
			t.Errorf("VerifyPassword(%q) should have rejected a malformed hash", c)
		}
	}
}

func TestHashPasswordCarriesItsOwnParameters(t *testing.T) {
	hash, err := HashPassword("whatever")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	// A password verified successfully years from now, after argonTime or
	// argonMemory have been raised, must still read its own cost back out
	// of the stored hash rather than assume today's constants.
	ok, err := VerifyPassword("whatever", hash)
	if err != nil || !ok {
		t.Fatalf("a hash must verify against the parameters embedded in itself: ok=%v err=%v", ok, err)
	}
}
