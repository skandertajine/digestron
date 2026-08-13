package config

import "log/slog"

// Secret is a string that never leaks: fmt, JSON and slog all render it
// redacted. Call Reveal() at the single point of use.
type Secret string

const redacted = "<redacted>"

func (s Secret) String() string   { return redacted }
func (s Secret) GoString() string { return redacted }

func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

func (s Secret) Reveal() string { return string(s) }
