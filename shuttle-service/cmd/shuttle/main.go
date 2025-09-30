package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/estroop3-gif/end-to-end-messenger/shuttle-service/internal/config"
	"github.com/estroop3-gif/end-to-end-messenger/shuttle-service/internal/server"
	"github.com/estroop3-gif/end-to-end-messenger/shuttle-service/internal/storage"
)

const (
	serviceName    = "shuttle-service"
	serviceVersion = "1.0.0"
)

func main() {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting shuttle service",
		zap.String("service", serviceName),
		zap.String("version", serviceVersion))

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	logger.Info("Configuration loaded",
		zap.String("redis_addr", cfg.Redis.Address),
		zap.String("server_addr", cfg.Server.Address),
		zap.Int("server_port", cfg.Server.Port),
		zap.Bool("auth_enabled", cfg.Auth.Enabled))

	// Initialize storage
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store, err := storage.NewRedisStorage(ctx, cfg.Redis, logger)
	if err != nil {
		logger.Fatal("Failed to initialize storage", zap.Error(err))
	}
	defer store.Close()

	logger.Info("Storage initialized successfully")

	// Test storage connection
	if err := store.Ping(ctx); err != nil {
		logger.Fatal("Storage ping failed", zap.Error(err))
	}

	logger.Info("Storage connection verified")

	// Initialize server
	srv, err := server.New(cfg, store, logger)
	if err != nil {
		logger.Fatal("Failed to initialize server", zap.Error(err))
	}

	// Start server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Starting HTTP server",
			zap.String("address", fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)))

		if err := srv.Start(); err != nil {
			serverErr <- fmt.Errorf("server failed to start: %w", err)
		}
	}()

	// Wait for server to start
	select {
	case err := <-serverErr:
		logger.Fatal("Server startup failed", zap.Error(err))
	case <-time.After(2 * time.Second):
		logger.Info("Server started successfully")
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal or server error
	select {
	case sig := <-sigChan:
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
	case err := <-serverErr:
		logger.Error("Server error", zap.Error(err))
	}

	// Graceful shutdown
	logger.Info("Initiating graceful shutdown...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop the server
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown failed", zap.Error(err))
	} else {
		logger.Info("Server shutdown completed")
	}

	// Stop storage
	if err := store.Close(); err != nil {
		logger.Error("Storage shutdown failed", zap.Error(err))
	} else {
		logger.Info("Storage shutdown completed")
	}

	logger.Info("Shuttle service stopped gracefully")
}