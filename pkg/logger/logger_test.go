package logger

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestNew_LevelParsing(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want zerolog.Level
	}{
		{"debug", zerolog.DebugLevel},
		{"info", zerolog.InfoLevel},
		{"warn", zerolog.WarnLevel},
		{"error", zerolog.ErrorLevel},
		{"", zerolog.InfoLevel},            // empty → info (not NoLevel)
		{"not-a-level", zerolog.InfoLevel}, // unparseable → info
	} {
		if got := New(tc.in).GetLevel(); got != tc.want {
			t.Errorf("New(%q) level = %v, want %v", tc.in, got, tc.want)
		}
	}
}
