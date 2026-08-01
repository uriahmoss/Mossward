//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows/svc/eventlog"
)

const windowsEventID = 100

type windowsEventLogHandler struct {
	log   *eventlog.Log
	attrs []slog.Attr
}

func newWindowsEventLogHandler(log *eventlog.Log) slog.Handler {
	return &windowsEventLogHandler{log: log}
}

func (handler *windowsEventLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (handler *windowsEventLogHandler) Handle(_ context.Context, record slog.Record) error {
	var message strings.Builder
	message.WriteString(record.Message)
	for _, attribute := range handler.attrs {
		appendWindowsLogAttribute(&message, attribute)
	}
	record.Attrs(func(attribute slog.Attr) bool {
		appendWindowsLogAttribute(&message, attribute)
		return true
	})
	if record.Level >= slog.LevelError {
		return handler.log.Error(windowsEventID, message.String())
	}
	if record.Level >= slog.LevelWarn {
		return handler.log.Warning(windowsEventID, message.String())
	}
	return handler.log.Info(windowsEventID, message.String())
}

func (handler *windowsEventLogHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	copy := &windowsEventLogHandler{log: handler.log, attrs: append([]slog.Attr{}, handler.attrs...)}
	copy.attrs = append(copy.attrs, attributes...)
	return copy
}

func (handler *windowsEventLogHandler) WithGroup(name string) slog.Handler {
	return handler.WithAttrs([]slog.Attr{slog.String("group", name)})
}

func appendWindowsLogAttribute(message *strings.Builder, attribute slog.Attr) {
	attribute.Value = attribute.Value.Resolve()
	message.WriteString(" ")
	message.WriteString(attribute.Key)
	message.WriteString("=")
	message.WriteString(fmt.Sprint(attribute.Value.Any()))
}
