package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

var BuildVersion = "dev"

func init() {
	// Set standardized log format: yyyy-mm-dd hh:mm:ss.sss+TZ
	log.SetFlags(0)
	log.SetOutput(os.Stderr)
	log.SetPrefix("")
}

func logf(format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000-07:00")
	log.Printf("[%s] "+format, append([]interface{}{timestamp}, args...)...)
}

func main() {
	conf := flag.String("config", "config.json", "path to config file or a http(s) url")
	version := flag.Bool("version", false, "print version and exit")
	help := flag.Bool("help", false, "print help and exit")
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}
	if *version {
		fmt.Println(BuildVersion)
		return
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
