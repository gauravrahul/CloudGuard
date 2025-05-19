package web

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"intrualert/types"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var (
	store *sessions.CookieStore
)

// InitSessionStore should be called when server starts
func InitSessionStore(secret string) {
	store = sessions.NewCookieStore([]byte(secret))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	}
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	stats := s.Analyzer.GetStatistics()
	log.Printf("Sending traffic stats: %+v", stats) // Add logging
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"traffic":   stats,
		"timestamp": time.Now().Unix(),
	})
}

func (s *Server) handleAttacks(w http.ResponseWriter, r *http.Request) {
	attacks, err := s.store.GetAttacks()
	if err != nil {
		log.Printf("Error fetching attacks: %v", err)
		// Return empty array instead of error
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"attacks":   []types.AttackLog{},
			"timestamp": time.Now().Unix(),
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"attacks":   attacks,
		"timestamp": time.Now().Unix(),
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	config := struct {
		Interfaces         []string `json:"interfaces"`
		Port               int      `json:"port"`
		SYNFloodThreshold  int      `json:"syn_flood_threshold"`
		UDPFloodThreshold  int      `json:"udp_flood_threshold"`
		ICMPFloodThreshold int      `json:"icmp_flood_threshold"`
		HTTPFloodThreshold int      `json:"http_flood_threshold"`
		MitigationEnabled  bool     `json:"mitigation_enabled"`
		StorageEnabled     bool     `json:"storage_enabled"`
	}{
		Interfaces:         s.cfg.Interfaces,
		Port:               s.cfg.Port,
		SYNFloodThreshold:  s.cfg.SYNFloodThreshold,
		UDPFloodThreshold:  s.cfg.UDPFloodThreshold,
		ICMPFloodThreshold: s.cfg.ICMPFloodThreshold,
		HTTPFloodThreshold: s.cfg.HTTPFloodThreshold,
		MitigationEnabled:  s.cfg.MitigationEnabled,
		StorageEnabled:     s.cfg.StorageEnabled,
	}
	respondJSON(w, http.StatusOK, config)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	err := r.ParseForm()
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid form data")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Admin credentials check - use "admin" for both username and password
	if username == "admin" && password == "admin" {
		session, err := store.Get(r, "session-name")
		if err != nil {
			// Create new session if getting existing one fails
			session, err = store.New(r, "session-name")
			if err != nil {
				log.Printf("Error creating session: %v", err)
				respondError(w, http.StatusInternalServerError, "Session error")
				return
			}
		}

		// Configure session
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7, // 7 days
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
		}

		// Set session values
		session.Values["authenticated"] = true
		session.Values["username"] = username

		// Save session
		if err := session.Save(r, w); err != nil {
			log.Printf("Error saving session: %v", err)
			respondError(w, http.StatusInternalServerError, "Failed to save session")
			return
		}

		// Send success response
		respondJSON(w, http.StatusOK, map[string]string{
			"status":   "success",
			"redirect": "/static/dashboard.html",
		})
		return
	}

	respondJSON(w, http.StatusUnauthorized, map[string]string{
		"error": "Invalid username or password",
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name") // Use the global store
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	err := r.ParseForm()
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid form data")
		return
	}
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if username == "" || email == "" || password == "" || confirmPassword == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "All fields are required"})
		return
	}
	if password != confirmPassword {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Passwords do not match"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	user := types.User{
		Username: username,
		Email:    email,
		Password: string(hashedPassword),
	}
	err = s.store.StoreUser(user)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Username or email already exists"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"redirect": "/login.html"})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var settings struct {
		SYNFloodThreshold  int  `json:"syn_flood_threshold"`
		UDPFloodThreshold  int  `json:"udp_flood_threshold"`
		ICMPFloodThreshold int  `json:"icmp_flood_threshold"`
		HTTPFloodThreshold int  `json:"http_flood_threshold"`
		MitigationEnabled  bool `json:"mitigation_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	s.cfg.SYNFloodThreshold = settings.SYNFloodThreshold
	s.cfg.UDPFloodThreshold = settings.UDPFloodThreshold
	s.cfg.ICMPFloodThreshold = settings.ICMPFloodThreshold
	s.cfg.HTTPFloodThreshold = settings.HTTPFloodThreshold
	s.cfg.MitigationEnabled = settings.MitigationEnabled

	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to save settings")
		return
	}
	if err := os.WriteFile("config/config.json", data, 0644); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to save settings")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "Settings updated"})
}

func (s *Server) handleMitigate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.wafClient.BlockIP(ctx, "192.168.1.100", "Manual mitigation")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to trigger mitigation")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "Mitigation triggered"})
}

func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.wafClient.Cleanup(ctx)
	respondJSON(w, http.StatusOK, map[string]string{"status": "Cleanup triggered"})
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
