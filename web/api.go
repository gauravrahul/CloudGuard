package web

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"intrualert/types"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Adjust for production
	},
}

func (s *Server) setupRoutes() {
	// Add debug logging
	s.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Request: %s %s", r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	})

	// Create a file server for static files
	fs := http.FileServer(http.Dir("web/static"))

	// Serve static files under /static/
	s.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	// API routes with auth middleware
	api := s.router.PathPrefix("/api").Subrouter()

	// Public routes (no auth required)
	api.HandleFunc("/login", s.handleLogin).Methods("POST")
	api.HandleFunc("/signup", s.handleSignup).Methods("POST")

	// Protected routes (require auth)
	protected := api.PathPrefix("").Subrouter()
	protected.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.authMiddleware(next.ServeHTTP)(w, r)
		})
	})

	// Add reports endpoints
	protected.HandleFunc("/reports/summary", s.handleReportsSummary).Methods("GET")
	protected.HandleFunc("/reports/export", s.handleReportsExport).Methods("GET")

	protected.HandleFunc("/logout", s.handleLogout).Methods("POST")
	protected.HandleFunc("/stats", s.handleTraffic).Methods("GET")
	protected.HandleFunc("/attacks", s.handleAttacks).Methods("GET")
	protected.HandleFunc("/config", s.handleConfig).Methods("GET")
	protected.HandleFunc("/settings", s.handleSettings).Methods("PATCH")
	protected.HandleFunc("/mitigate", s.handleMitigate).Methods("POST")
	protected.HandleFunc("/cleanup", s.handleCleanup).Methods("POST")

	// WebSocket endpoint (requires auth)
	s.router.Handle("/ws", s.authMiddleware(s.handleWebSocket))

	// Redirect root to login page
	s.router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/static/login.html", http.StatusSeeOther)
			return
		}
		http.NotFound(w, r)
	})
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow static files without authentication
		if strings.HasPrefix(r.URL.Path, "/static/") ||
			r.URL.Path == "/api/login" ||
			r.URL.Path == "/api/signup" {
			next(w, r)
			return
		}

		// Check session
		session, err := store.Get(r, "session-name")
		if err != nil {
			log.Printf("Session error: %v", err)
			http.Redirect(w, r, "/static/login.html", http.StatusSeeOther)
			return
		}

		// Verify authentication
		auth, ok := session.Values["authenticated"].(bool)
		if !ok || !auth {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/static/login.html", http.StatusSeeOther)
			}
			return
		}

		next(w, r)
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// Register client with the hub
	s.hub.register <- conn

	// Send initial data
	if s.Analyzer != nil {
		stats := s.Analyzer.GetStatistics()
		s.hub.BroadcastStats(stats)
	}

	// Monitor connection
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			s.hub.unregister <- conn
			return
		}
	}
}

func (s *Server) handleReportsSummary(w http.ResponseWriter, r *http.Request) {
	// Parse time range from query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		start = time.Now().AddDate(0, 0, -7) // Default to last 7 days
	}
	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		end = time.Now()
	}

	// Get attacks within time range
	attacks, err := s.store.GetAttacksByTimeRange(start, end)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch attack data")
		return
	}

	// Calculate metrics
	metrics := calculateMetrics(attacks)

	respondJSON(w, http.StatusOK, metrics)
}

func (s *Server) handleReportsExport(w http.ResponseWriter, r *http.Request) {
	// Parse time range and format
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")
	format := r.URL.Query().Get("format")

	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		start = time.Now().AddDate(0, 0, -7)
	}
	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		end = time.Now()
	}

	// Get attacks within time range
	attacks, err := s.store.GetAttacksByTimeRange(start, end)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch attack data")
		return
	}

	// Export based on format
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=attack-report.csv")
		csvWriter := csv.NewWriter(w)
		csvWriter.Write([]string{"Timestamp", "Source IP", "Destination IP", "Protocol", "Description", "Severity", "Mitigated"})
		for _, attack := range attacks {
			csvWriter.Write([]string{
				attack.Timestamp,
				attack.SourceIP,
				attack.DestinationIP,
				attack.Protocol,
				attack.Description,
				attack.Severity,
				fmt.Sprintf("%v", attack.Mitigated),
			})
		}
		csvWriter.Flush()
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=attack-report.json")
		json.NewEncoder(w).Encode(attacks)
	default:
		respondError(w, http.StatusBadRequest, "Unsupported export format")
	}
}

func calculateMetrics(attacks []types.AttackLog) map[string]interface{} {
	totalAttacks := len(attacks)
	attackTypes := make(map[string]int)
	successfulMitigations := 0
	blockedIPs := make(map[string]bool)

	for _, attack := range attacks {
		// Count attack types
		attackTypes[attack.Description]++

		// Count mitigations
		if attack.Mitigated {
			successfulMitigations++
		}

		// Track unique blocked IPs
		blockedIPs[attack.SourceIP] = true
	}

	// Find most common attack
	mostCommonAttack := ""
	maxCount := 0
	for aType, count := range attackTypes {
		if count > maxCount {
			maxCount = count
			mostCommonAttack = aType
		}
	}

	return map[string]interface{}{
		"total_attacks":          totalAttacks,
		"successful_mitigations": successfulMitigations,
		"blocked_ips":            len(blockedIPs),
		"most_common_attack": map[string]interface{}{
			"type":  mostCommonAttack,
			"count": maxCount,
		},
		"attack_types_distribution": attackTypes,
		"mitigation_rate":           float64(successfulMitigations) / float64(totalAttacks) * 100,
	}
}
