package config

// SecureString holds a sensitive value (e.g. an API password) in a mutable byte
// buffer that can be zeroed via Clear, limiting how long the secret lingers in
// memory. It does not prevent the value from being copied into an immutable Go
// string when String() is called — callers should avoid that on hot paths.
type SecureString struct {
	b []byte
}

// NewSecureString wraps a string value. The string's bytes are copied into the
// mutable buffer.
func NewSecureString(s string) *SecureString {
	return &SecureString{b: []byte(s)}
}

// NewSecureStringFromBytes copies the given bytes into a new SecureString so the
// caller can safely zero its own buffer afterwards.
func NewSecureStringFromBytes(b []byte) *SecureString {
	cp := make([]byte, len(b))
	copy(cp, b)
	return &SecureString{b: cp}
}

// String implements fmt.Stringer and deliberately REDACTS the secret so it is
// never accidentally leaked through %v/%s formatting or structured logging. Use
// Reveal to obtain the real value.
func (s *SecureString) String() string {
	if s.Empty() {
		return ""
	}
	return "[REDACTED]"
}

// Reveal returns the real secret value. This copies the secret into an immutable
// string that Clear cannot scrub, so call it only at the point of use (e.g. when
// building an auth header) and avoid retaining the result.
func (s *SecureString) Reveal() string {
	if s == nil {
		return ""
	}
	return string(s.b)
}

// Bytes returns the underlying buffer (not a copy). Do not retain it across a
// Clear.
func (s *SecureString) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.b
}

// Empty reports whether the SecureString holds no value.
func (s *SecureString) Empty() bool {
	return s == nil || len(s.b) == 0
}

// Clear zeroes the backing buffer. It is safe to call multiple times and on a
// nil receiver.
func (s *SecureString) Clear() {
	if s == nil {
		return
	}
	for i := range s.b {
		s.b[i] = 0
	}
	s.b = s.b[:0]
}
