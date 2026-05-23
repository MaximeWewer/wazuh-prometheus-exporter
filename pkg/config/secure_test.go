package config

import "testing"

func TestSecureString_RoundTripAndClear(t *testing.T) {
	s := NewSecureString("hunter2")
	if got := s.Reveal(); got != "hunter2" {
		t.Fatalf("Reveal() = %q, want %q", got, "hunter2")
	}
	if got := s.String(); got != "[REDACTED]" {
		t.Fatalf("String() = %q, want it to redact the secret", got)
	}
	if s.Empty() {
		t.Fatal("Empty() = true, want false")
	}

	b := s.Bytes()
	s.Clear()

	for i := range b {
		if b[i] != 0 {
			t.Fatalf("byte %d not zeroed after Clear", i)
		}
	}
	if !s.Empty() {
		t.Fatal("Empty() = false after Clear, want true")
	}

	s.Clear() // must be a no-op, not a panic
}

func TestNewSecureStringFromBytes_Copies(t *testing.T) {
	src := []byte("abc")
	s := NewSecureStringFromBytes(src)
	src[0] = 'X' // mutate caller's buffer
	if got := s.Reveal(); got != "abc" {
		t.Fatalf("Reveal() = %q, want %q (SecureString must copy)", got, "abc")
	}
}

func TestSecureString_NilSafe(t *testing.T) {
	var s *SecureString
	if !s.Empty() {
		t.Fatal("nil SecureString should be Empty")
	}
	if s.String() != "" {
		t.Fatal("nil SecureString String() should be empty")
	}
	if s.Reveal() != "" {
		t.Fatal("nil SecureString Reveal() should be empty")
	}
	s.Clear() // must not panic
}
