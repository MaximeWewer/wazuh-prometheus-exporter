// Package logger provides a thin wrapper around zerolog for structured,
// JSON-formatted logging used across the exporter.
package logger

import (
	"os"

	"github.com/rs/zerolog"
)

// New returns a structured logger writing JSON to stdout at the given level.
// Unrecognized levels fall back to info.
func New(level string) zerolog.Logger {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil || level == "" {
		// zerolog.ParseLevel("") returns NoLevel with a nil error, which would
		// disable level filtering; treat empty/unparseable input as info.
		lvl = zerolog.InfoLevel
	}
	return zerolog.New(os.Stdout).Level(lvl).With().Timestamp().Logger()
}
