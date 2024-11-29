package slogx

import "log/slog"

func StringPtr(key string, value *string) slog.Attr {
	if value != nil {
		return slog.String(key, *value)
	}
	return slog.Any(key, nil)
}
