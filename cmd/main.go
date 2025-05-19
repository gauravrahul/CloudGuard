package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"intrualert/config" // Add this import
	"intrualert/detection"
	"intrualert/mitigation"
	"intrualert/storage"
	"intrualert/types"
	"intrualert/web"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config" // Rename to avoid conflict
)

func main() {
	// Validate AWS credentials first
	if err := validateAWSCredentials(); err != nil {
		log.Fatalf("AWS credentials validation failed: %v", err)
	}

	// Load config
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Configure AWS SDK
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithRetryMaxAttempts(5),
		awsconfig.WithRetryMode(aws.RetryModeStandard),
	)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Initialize storage
	store, err := storage.NewStorage(awsCfg)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Initialize WAF client
	wafClient, err := mitigation.NewWAFClient(awsCfg, cfg.WAF)
	if err != nil {
		log.Fatalf("Failed to initialize WAF client: %v", err)
	}

	signatures, err := types.LoadSignatures(cfg.SignatureFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load signatures: %v\n", err)
		os.Exit(1)
	}

	if err := wafClient.Initialize(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize WAF client: %v\n", err)
		os.Exit(1)
	}

	// Create a root context with cancellation
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	// Initialize components with the root context
	hub := web.NewWebSocketHub()
	go hub.Run()

	server, err := web.NewServer(cfg, nil, store, wafClient, hub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize server: %v\n", err)
		os.Exit(1)
	}

	analyzer, err := detection.NewAnalyzer(cfg, signatures, wafClient, store, hub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize analyzer: %v\n", err)
		os.Exit(1)
	}

	server.SetAnalyzer(analyzer)

	log.Printf("Starting CloudGuard DDoS Protection System")
	log.Printf("Version: 1.0.0")
	log.Printf("Initializing components...")

	// Start packet capture workers
	for _, iface := range cfg.Interfaces {
		go func(iface string) {
			if err := detection.CapturePackets(rootCtx, iface, analyzer); err != nil {
				if err != context.Canceled {
					fmt.Fprintf(os.Stderr, "Packet capture error on %s: %v\n", iface, err)
				}
			}
		}(iface)
	}

	// Graceful shutdown handler
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		log.Println("\nInitiating graceful shutdown...")

		// Create shutdown context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Cancel root context first
		rootCancel()

		// 1. Stop accepting new WebSocket connections
		hub.Shutdown()
		log.Println("✓ WebSocket connections closed")

		// 2. Stop the analyzer
		analyzer.Shutdown()
		log.Println("✓ Packet analyzer stopped")

		// 3. Shutdown HTTP server
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("× HTTP server shutdown error: %v", err)
		} else {
			log.Println("✓ HTTP server stopped")
		}

		// 4. Clean up WAF rules
		if err := wafClient.Cleanup(ctx); err != nil {
			log.Printf("× WAF cleanup error: %v", err)
		} else {
			log.Println("✓ WAF rules cleaned up")
		}

		log.Println("Shutdown complete")
		os.Exit(0)
	}()

	// Start HTTP server
	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			rootCancel() // Cancel everything if server fails
		}
	}()

	// Wait for shutdown signal
	stop = make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	fmt.Println("\nShutdown initiated...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Cancel root context to stop packet capture
	rootCancel()

	// Shutdown components in order
	log.Println("Shutting down components...")

	// 1. Stop accepting new WebSocket connections
	hub.Shutdown()
	log.Println("WebSocket hub shutdown complete")

	// 2. Stop the analyzer (stops accepting new packets)
	analyzer.Shutdown()
	log.Println("Analyzer shutdown complete")

	// 3. Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	} else {
		log.Println("HTTP server shutdown complete")
	}

	// 4. Clean up WAF rules
	if err := wafClient.Cleanup(shutdownCtx); err != nil {
		log.Printf("WAF cleanup error: %v", err)
	} else {
		log.Println("WAF cleanup complete")
	}

	log.Println("Shutdown complete")
}

func validateAWSCredentials() error {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set")
	}
	return nil
}
