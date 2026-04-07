package main

import (
	"context"
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/dashboardapi"
	"github.com/joho/godotenv"
)

//go:embed static/*
var staticFS embed.FS

func main() {
	// Load .env from cwd when present (ignored by Docker/Kubernetes when env is injected).
	_ = godotenv.Load()

	addr := flag.String("listen", ":8080", "HTTP listen address")
	mongoURI := flag.String("mongo-uri", resolveMongoURI(), "MongoDB connection URI (default: MONGODB_URI env, else built from MONGO_ROOT_* + MONGO_HOST)")
	dbName := flag.String("mongo-db", getenv("MONGODB_DATABASE", "owasp_dashboard"), "MongoDB database name")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := dashboardapi.NewStore(ctx, *mongoURI, *dbName)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer func() {
		_ = store.Close(context.Background())
	}()

	h := &dashboardapi.Handler{Store: store}
	mux := http.NewServeMux()
	dashboardapi.RegisterRoutes(mux, h)

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           withLogging(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("dashboard listening on %s (mongo db=%s)", *addr, *dbName)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
