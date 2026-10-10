//go:build windows

package main

import (
	"context"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows/svc/eventlog"
)

type workerEventLog struct {
	log        *eventlog.Log
	attributes []slog.Attr
}

func (*workerEventLog) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}
func (handler *workerEventLog) Handle(_ context.Context, record slog.Record) error {
	parts := []string{record.Message}
	appendAttribute := func(attr slog.Attr) bool {
		parts = append(parts, attr.Key+"="+attr.Value.Resolve().String())
		return true
	}
	for _, attr := range handler.attributes {
		appendAttribute(attr)
	}
	record.Attrs(appendAttribute)
	message := strings.Join(parts, " ")
	if record.Level >= slog.LevelError {
		return handler.log.Error(100, message)
	}
	if record.Level >= slog.LevelWarn {
		return handler.log.Warning(100, message)
	}
	return handler.log.Info(100, message)
}
func (handler *workerEventLog) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := append([]slog.Attr{}, handler.attributes...)
	return &workerEventLog{log: handler.log, attributes: append(combined, attrs...)}
}
func (handler *workerEventLog) WithGroup(name string) slog.Handler {
	return handler.WithAttrs([]slog.Attr{slog.String("group", name)})
}
