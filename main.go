package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"
)

var BuildVersion = "dev"

func init() {
	// Set standardized log format: yyyy-mm-dd hh:mm:ss.sss+TZ
	log.SetFlags(0)
	log.SetOutput(os.Stderr)
	log.SetPrefix("")
}

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
func logf(format string, args ...interface{}) {
	logger.Info(fmt.Sprintf(format, args...))
}

func logError(format string, args ...interface{}) {
	logger.Error(fmt.Sprintf(format, args...))
}

func logWarn(format string, args ...interface{}) {
	logger.Warn(fmt.Sprintf(format, args...))
}

func logDebug(format string, args ...interface{}) {
	logger.Debug(fmt.Sprintf(format, args...))
}

func logTrace(format string, args ...interface{}) {
	// Use Debug level for trace since slog doesn't have trace
	logger.Debug(fmt.Sprintf(format, args...))
}

// Structured logging functions with component and fields
func logInfoWithFields(component, message string, fields map[string]interface{}) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Info(message, args...)
}

func logErrorWithFields(component, message string, fields map[string]interface{}) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Error(message, args...)
}

func logTraceWithFields(component, message string, fields map[string]interface{}) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Debug(message, args...)
}

func generateDefaultConfig(path string) error {
	defaultConfig := map[string]interface{}{
		"mcpProxy": map[string]interface{}{
			"baseURL": "http://localhost:8080",
			"addr":    ":8080",
			"name":    "mcp-front",
		},
		"mcpServers": map[string]interface{}{
			"postgres": map[string]interface{}{
				"command": "docker",
				"args": []string{
					"run", "--rm", "-i", "--network", "host",
					"mcp/postgres", "postgresql://user:password@localhost:5432/database",
				},
				"options": map[string]interface{}{
					"authTokens":  []string{"your-secret-token"},
					"logEnabled": true,
				},
			},
		},
		"oauth": map[string]interface{}{
			"issuer":             "https://your-domain.com",
			"gcpProject":        "your-gcp-project",
			"allowedDomains":    []string{"your-company.com"},
			"tokenTtl":          "24h",
			"storage":            "memory",
			"googleClientId":     "your-google-client-id",
			"googleClientSecret": "your-google-client-secret",
			"googleRedirectUri":  "https://your-domain.com/oauth/callback",
		},
	}

	data, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func main() {
	conf := flag.String("config", "", "path to config file (required)")
	version := flag.Bool("version", false, "print version and exit")
	help := flag.Bool("help", false, "print help and exit")
	configInit := flag.String("config-init", "", "generate default config file at specified path")
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}
	if *version {
		fmt.Println(BuildVersion)
		return
	}
	if *configInit != "" {
		if err := generateDefaultConfig(*configInit); err != nil {
			logf("Failed to generate config: %v", err)
			os.Exit(1)
		}
		fmt.Printf("Generated default config at: %s\n", *configInit)
		return
	}
	
	if *conf == "" {
		fmt.Fprintf(os.Stderr, "Error: -config flag is required\n")
		fmt.Fprintf(os.Stderr, "Run with -help for usage information\n")
		os.Exit(1)
	}
	
	config, err := load(*conf)
	if err != nil {
		logf("Failed to load config: %v", err)
		os.Exit(1)
	}
	err = startHTTPServer(config)
	if err != nil {
		logf("Failed to start server: %v", err)
		os.Exit(1)
	}
}
