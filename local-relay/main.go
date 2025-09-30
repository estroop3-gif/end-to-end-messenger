// Local Relay for Triple-Encryption Onion Transport
// Handles Layer C decryption and forwards to shuttle service

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"local-relay/internal/config"
	"local-relay/internal/relay"
	"local-relay/internal/shuttle"

	"go.uber.org/zap"
)

var (
	configPath = flag.String("config", "config.json", "Path to configuration file")
	port       = flag.Int("port", 8080, "Port to listen on")
	logLevel   = flag.String("log", "info", "Log level (debug, info, warn, error)")
)

func main() {
	flag.Parse()

	// Initialize logger
	logger := initLogger(*logLevel)
	defer logger.Sync()

	logger.Info("Starting Local Relay for Onion Transport",
		zap.String("version", "1.0.0"),
		zap.Int("port", *port),
		zap.String("config", *configPath))

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Override port if specified
	if *port != 8080 {
		cfg.Server.Port = *port
	}

	// Initialize shuttle client
	shuttleClient := shuttle.NewClient(cfg.Shuttle, logger)

	// Initialize relay server
	relayServer := relay.NewServer(cfg, shuttleClient, logger)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      relayServer.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("Local relay server starting", zap.Int("port", cfg.Server.Port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	logger.Info("Shutting down local relay server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Local relay server stopped")
}

func initLogger(level string) *zap.Logger {
	var cfg zap.Config

	if level == "debug" {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
	}

	// Parse log level
	switch level {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, err := cfg.Build()
	if err != nil {
		log.Fatal("Failed to initialize logger:", err)
	}

	return logger
}