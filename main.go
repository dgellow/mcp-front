package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
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

// Log levels for different types of output
const (
	LogLevelError = 0
	LogLevelWarn  = 1
	LogLevelInfo  = 2
	LogLevelDebug = 3
	LogLevelTrace = 4
)

var logLevel = LogLevelInfo // Default log level

func init() {
	// Check LOG_LEVEL environment variable
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		switch strings.ToUpper(level) {
		case "ERROR":
			logLevel = LogLevelError
		case "WARN", "WARNING":
			logLevel = LogLevelWarn
		case "INFO":
			logLevel = LogLevelInfo
		case "DEBUG":
			logLevel = LogLevelDebug
		case "TRACE":
			logLevel = LogLevelTrace
		}
	}
}

func logf(format string, args ...interface{}) {
	logAtLevel(LogLevelInfo, format, args...)
}

func logError(format string, args ...interface{}) {
	logAtLevel(LogLevelError, "[ERROR] "+format, args...)
}

func logWarn(format string, args ...interface{}) {
	logAtLevel(LogLevelWarn, "[WARN] "+format, args...)
}

func logDebug(format string, args ...interface{}) {
	logAtLevel(LogLevelDebug, "[DEBUG] "+format, args...)
}

func logTrace(format string, args ...interface{}) {
	logAtLevel(LogLevelTrace, "[TRACE] "+format, args...)
}

func logAtLevel(level int, format string, args ...interface{}) {
	if level <= logLevel {
		timestamp := time.Now().Format("2006-01-02 15:04:05.000-07:00")
		log.Printf("[%s] "+format, append([]interface{}{timestamp}, args...)...)
	}
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
