//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows/svc/eventlog"
)

const agentWindowsEventID = 100

type agentWindowsEventLogHandler struct {
	log   *eventlog.Log
	attrs []slog.Attr
}

func newAgentWindowsEventLogHandler(log *eventlog.Log) slog.Handler {
	return &agentWindowsEventLogHandler{log: log}
}

func (handler *agentWindowsEventLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (handler *agentWindowsEventLogHandler) Handle(_ context.Context, record slog.Record) error {
	var message strings.Builder
	message.WriteString(record.Message)
	for _, attribute := range handler.attrs {
		appendAgentWindowsLogAttribute(&message, attribute)
	}
	record.Attrs(func(attribute slog.Attr) bool {
		appendAgentWindowsLogAttribute(&message, attribute)
		return true
	})
	if record.Level >= slog.LevelError {
		return handler.log.Error(agentWindowsEventID, message.String())
	}
	if record.Level >= slog.LevelWarn {
		return handler.log.Warning(agentWindowsEventID, message.String())
	}
	return handler.log.Info(agentWindowsEventID, message.String())
}

func (handler *agentWindowsEventLogHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	copy := &agentWindowsEventLogHandler{log: handler.log, attrs: append([]slog.Attr{}, handler.attrs...)}
	copy.attrs = append(copy.attrs, attributes...)
	return copy
}

func (handler *agentWindowsEventLogHandler) WithGroup(name string) slog.Handler {
	return handler.WithAttrs([]slog.Attr{slog.String("group", name)})
}

func appendAgentWindowsLogAttribute(message *strings.Builder, attribute slog.Attr) {
	attribute.Value = attribute.Value.Resolve()
	message.WriteString(" ")
	message.WriteString(attribute.Key)
	message.WriteString("=")
	message.WriteString(fmt.Sprint(attribute.Value.Any()))
}
