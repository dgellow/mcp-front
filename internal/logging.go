package internal

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

var logger *slog.Logger

func init() {
	// Configure structured logging using Go's standard slog package
	var level slog.Level

	// Check LOG_LEVEL environment variable
	switch strings.ToUpper(os.Getenv("LOG_LEVEL")) {
	case "ERROR":
		level = slog.LevelError
	case "WARN", "WARNING":
		level = slog.LevelWarn
	case "INFO", "":
		level = slog.LevelInfo
	case "DEBUG":
		level = slog.LevelDebug
	default:
		level = slog.LevelInfo
	}

	// Check LOG_FORMAT environment variable
	var handler slog.Handler
	if strings.ToUpper(os.Getenv("LOG_FORMAT")) == "JSON" {
		// Production: structured JSON logs
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Customize timestamp format
				if a.Key == slog.TimeKey {
					return slog.Attr{
						Key:   "timestamp",
						Value: slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano)),
					}
				}
				return a
			},
		})
	} else {
		// Development: human-readable text logs
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Customize timestamp format for readability
				if a.Key == slog.TimeKey {
					return slog.Attr{
						Key:   slog.TimeKey,
						Value: slog.StringValue(a.Value.Time().Format("2006-01-02 15:04:05.000-07:00")),
					}
				}
				return a
			},
		})
	}

	logger = slog.New(handler)
	slog.SetDefault(logger)
}

// Convenience functions using standard slog with component context
func Logf(format string, args ...interface{}) {
	logger.Info(fmt.Sprintf(format, args...))
}

func LogError(format string, args ...interface{}) {
	logger.Error(fmt.Sprintf(format, args...))
}

func LogWarn(format string, args ...interface{}) {
	logger.Warn(fmt.Sprintf(format, args...))
}

func LogDebug(format string, args ...interface{}) {
	logger.Debug(fmt.Sprintf(format, args...))
}

func LogTrace(format string, args ...interface{}) {
	// Use Debug level for trace since slog doesn't have trace
	logger.Debug(fmt.Sprintf(format, args...))
}

// Structured logging functions with component and fields
func LogInfoWithFields(component, message string, fields map[string]interface{}) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Info(message, args...)
}

func LogDebugWithFields(component, message string, fields map[string]interface{}) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Debug(message, args...)
}

func LogErrorWithFields(component, message string, fields map[string]interface{}) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Error(message, args...)
}

func LogWarnWithFields(component, message string, fields map[string]interface{}) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Warn(message, args...)
}

func LogTraceWithFields(component, message string, fields map[string]interface{}) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Debug(message, args...)
}
