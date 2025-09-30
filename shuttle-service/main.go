// Shuttle Service for Triple-Encryption Onion Transport
// Implements offer/claim API for message queuing between relays

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

	"shuttle-service/internal/config"
	"shuttle-service/internal/queue"
	"shuttle-service/internal/server"
	"shuttle-service/internal/storage"

	"go.uber.org/zap"
)

var (
	configPath = flag.String("config", "config.json", "Path to configuration file")
	port       = flag.Int("port", 8081, "Port to listen on")
	logLevel   = flag.String("log", "info", "Log level (debug, info, warn, error)")
)

func main() {
	flag.Parse()

	// Initialize logger
	logger := initLogger(*logLevel)
	defer logger.Sync()

	logger.Info("Starting Shuttle Service for Onion Transport",
		zap.String("version", "1.0.0"),
		zap.Int("port", *port),
		zap.String("config", *configPath))

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Override port if specified
	if *port != 8081 {
		cfg.Server.Port = *port
	}

	// Initialize storage
	store, err := storage.NewRedisStorage(cfg.Redis, logger)
	if err != nil {
		logger.Fatal("Failed to initialize storage", zap.Error(err))
	}
	defer store.Close()

	// Initialize message queue
	messageQueue := queue.NewMessageQueue(store, cfg.Queue, logger)

	// Initialize HTTP server
	httpServer := server.NewServer(cfg, messageQueue, logger)

	// Setup HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      httpServer.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
		logger.Info("Shuttle service starting", zap.Int("port", cfg.Server.Port))
		if cfg.Server.EnableTLS {
			if err := srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != nil && err != http.ErrServerClosed {
				logger.Fatal("Failed to start TLS server", zap.Error(err))
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("Failed to start server", zap.Error(err))
			}
		}
	}()

	// Start background cleanup
	go messageQueue.StartCleanup()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	logger.Info("Shutting down shuttle service...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop background tasks
	messageQueue.StopCleanup()

	// Shutdown HTTP server
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Shuttle service stopped")
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