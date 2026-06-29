package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/neuf/registry-ui/backend/internal/config"
	"github.com/neuf/registry-ui/backend/internal/server"
	"github.com/neuf/registry-ui/backend/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	for _, dir := range []string{cfg.DataDir, cfg.UploadDir, cfg.CertDir, cfg.RegistryDataDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("create data dir %s: %v", dir, err)
		}
	}

	st, err := store.Open(cfg.SQLitePath)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer st.Close()

	srv := server.New(cfg, st)

	// Start background daily GC
	go startBackgroundGC(srv)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	httpServer := &http.Server{
		Addr:              cfg.ServerAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: server.DefaultReadHeaderTimeout,
	}

	// One-shot startup sync: pull catalog + tags + digest from the registry
	// into the images table. Runs in the background so it never blocks startup.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := srv.SyncAll(ctx); err != nil {
			log.Printf("startup sync failed: %v", err)
		}
	}()

	// TLS is managed entirely via the UI toggle (tls_enabled setting) plus a
	// cert/key pair stored in CERT_DIR. When enabled and present, we serve
	// HTTPS with a TLS 1.2 floor; otherwise we serve plain HTTP.
	tlsReady := srv.TLSReady()
	go func() {
		var err error
		if tlsReady {
			log.Printf("Registry UI listening on %s (tls=on)", cfg.ServerAddr)
			httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			err = httpServer.ListenAndServeTLS(srv.CertPath(), srv.KeyPath())
		} else {
			log.Printf("Registry UI listening on %s (tls=off)", cfg.ServerAddr)
			err = httpServer.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutdown signal received, draining connections...")
		drain(httpServer)
		log.Printf("server stopped")
	case <-srv.RestartRequested():
		log.Printf("restart requested, draining connections...")
		drain(httpServer)
		execSelf()
	}
}

// drain gracefully shuts down the HTTP server with a 5s deadline.
func drain(httpServer *http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

// execSelf replaces the current process image with a fresh copy of the same
// binary (same args/env). The PID is preserved, so in a container the
// supervising entrypoint and sibling processes (e.g. the registry in AIO
// mode) are unaffected. The new process re-reads settings, so TLS changes
// take effect.
func execSelf() {
	bin, err := os.Executable()
	if err != nil {
		log.Fatalf("restart: cannot resolve executable: %v", err)
	}
	log.Printf("restarting: exec %s", bin)
	if err := syscall.Exec(bin, os.Args, os.Environ()); err != nil {
		log.Fatalf("restart: exec failed: %v", err)
	}
}

// startBackgroundGC runs daily GC to clean up expired recycle bin items
func startBackgroundGC(srv *server.Server) {
	log.Printf("Background GC started, will run daily")
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Run once on startup
	runGC(srv)

	for range ticker.C {
		runGC(srv)
	}
}

func runGC(srv *server.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	deleted, err := srv.RunRegistryGC(ctx, false)
	if err != nil {
		log.Printf("background GC failed: %v", err)
	} else {
		log.Printf("background GC completed: deleted %d items", deleted)
	}
	// Run blob GC to reclaim storage
	blobCtx, blobCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer blobCancel()
	blobDeleted, freed, err := srv.RunBlobGC(blobCtx)
	if err != nil {
		log.Printf("background blob GC failed: %v", err)
	} else {
		log.Printf("background blob GC completed: deleted %d blobs, freed %d bytes", blobDeleted, freed)
	}
}

