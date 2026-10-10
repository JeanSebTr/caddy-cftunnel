package cftunnel

import (
	"encoding/json"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// zapWriter turns cloudflared's zerolog JSON events into zap entries. The
// target logger is swapped on every config reload, because a pooled tunnel
// outlives the Caddy context whose logger it was created with.
type zapWriter struct {
	logger atomic.Pointer[zap.Logger]
}

func newZapWriter(l *zap.Logger) *zapWriter {
	w := &zapWriter{}
	w.logger.Store(l)
	return w
}

func (w *zapWriter) setLogger(l *zap.Logger) { w.logger.Store(l) }

func (w *zapWriter) Write(p []byte) (int, error) {
	return w.WriteLevel(zerolog.NoLevel, p)
}

func (w *zapWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	l := w.logger.Load()
	lvl := zapLevel(level)
	if !l.Core().Enabled(lvl) {
		return len(p), nil
	}

	var event map[string]any
	if err := json.Unmarshal(p, &event); err != nil {
		l.Log(lvl, strings.TrimSpace(string(p)))
		return len(p), nil
	}
	msg, _ := event[zerolog.MessageFieldName].(string)
	delete(event, zerolog.MessageFieldName)
	delete(event, zerolog.LevelFieldName)
	delete(event, zerolog.TimestampFieldName)

	keys := make([]string, 0, len(event))
	for k := range event {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fields := make([]zap.Field, 0, len(keys))
	for _, k := range keys {
		fields = append(fields, zap.Any(k, event[k]))
	}
	l.Log(lvl, msg, fields...)
	return len(p), nil
}

// zapLevel maps zerolog levels to zap. Fatal and panic are downgraded to
// error: a library must never exit Caddy through the logger.
func zapLevel(l zerolog.Level) zapcore.Level {
	switch l {
	case zerolog.TraceLevel, zerolog.DebugLevel:
		return zapcore.DebugLevel
	case zerolog.WarnLevel:
		return zapcore.WarnLevel
	case zerolog.ErrorLevel, zerolog.FatalLevel, zerolog.PanicLevel:
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}
