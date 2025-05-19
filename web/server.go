package web

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"intrualert/detection"
	"intrualert/mitigation"
	"intrualert/storage"
	"intrualert/types"

	"github.com/gorilla/mux"
)

type Server struct {
	cfg       *types.Config
	Analyzer  *detection.Analyzer
	store     *storage.Storage
	wafClient *mitigation.WAFClient
	router    *mux.Router
	hub       *WebSocketHub
	server    *http.Server
}

func NewServer(cfg *types.Config, analyzer *detection.Analyzer, store *storage.Storage, wafClient *mitigation.WAFClient, hub *WebSocketHub) (*Server, error) {
	// Initialize session store with config secret
	sessionSecret := cfg.SessionSecret
	if sessionSecret == "" {
		sessionSecret = "RIitbl2CWLJMTZcYFG5qsfyD8Pgam0jE3z7Xo6O9wp4udHNKAnSUQk1rVehvxB"
	}
	InitSessionStore(sessionSecret)

	s := &Server{
		cfg:       cfg,
		Analyzer:  analyzer,
		store:     store,
		wafClient: wafClient,
		router:    mux.NewRouter(),
		hub:       hub,
	}
	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: s.router,
	}

	s.setupRoutes()
	return s, nil
}

func (s *Server) SetAnalyzer(analyzer *detection.Analyzer) {
	s.Analyzer = analyzer
}

func (s *Server) Start() error {
	log.Printf("Starting web server on :%d", s.cfg.Port)
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("Shutting down web server")
	return s.server.Shutdown(ctx)
}
