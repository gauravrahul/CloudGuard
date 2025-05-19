package web

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"intrualert/types"

	"github.com/gorilla/websocket"
)

type ThreatSummary struct {
	Protocol      string         `json:"protocol"`
	Count         int            `json:"count"`
	Severity      string         `json:"severity"`
	Mitigated     int            `json:"mitigated"`
	Active        int            `json:"active"`
	LastSeen      time.Time      `json:"last_seen"`
	AttacksByType map[string]int `json:"attacks_by_type"`
}

type WebSocketHub struct {
	clients     map[*websocket.Conn]bool
	broadcast   chan interface{}
	register    chan *websocket.Conn
	unregister  chan *websocket.Conn
	mu          sync.Mutex
	done        chan struct{}
	threatStats map[string]*ThreatSummary
	statsMu     sync.RWMutex
}

func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients:     make(map[*websocket.Conn]bool),
		broadcast:   make(chan interface{}, 100),
		register:    make(chan *websocket.Conn),
		unregister:  make(chan *websocket.Conn),
		done:        make(chan struct{}),
		threatStats: make(map[string]*ThreatSummary),
	}
}

func (h *WebSocketHub) Run() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.done:
			h.closeAllConnections()
			return
		case client := <-h.register:
			h.addClient(client)
		case client := <-h.unregister:
			h.removeClient(client)
		case message := <-h.broadcast:
			h.broadcastMessage(message)
		case <-ticker.C:
			// Send periodic updates
			h.broadcastThreatSummary()
		}
	}
}

func (h *WebSocketHub) addClient(client *websocket.Conn) {
	h.mu.Lock()
	h.clients[client] = true
	h.mu.Unlock()
	log.Printf("WebSocket client connected: %d active", len(h.clients))
}

func (h *WebSocketHub) removeClient(client *websocket.Conn) {
	h.mu.Lock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		client.Close()
	}
	h.mu.Unlock()
	log.Printf("WebSocket client disconnected: %d active", len(h.clients))
}

func (h *WebSocketHub) closeAllConnections() {
	h.mu.Lock()
	for client := range h.clients {
		client.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second))
		client.Close()
	}
	h.clients = make(map[*websocket.Conn]bool)
	h.mu.Unlock()
}

func (h *WebSocketHub) broadcastMessage(message interface{}) {
	wsMessage := struct {
		Type      string      `json:"type"`
		Data      interface{} `json:"data"`
		Timestamp int64       `json:"timestamp"`
	}{
		Timestamp: time.Now().Unix(),
	}

	switch msg := message.(type) {
	case types.TrafficStats:
		wsMessage.Type = "stats"
		wsMessage.Data = struct {
			SYNPackets  int `json:"syn_packets"`
			TCPPackets  int `json:"tcp_packets"`
			UDPPackets  int `json:"udp_packets"`
			ICMPPackets int `json:"icmp_packets"`
			HTTPPackets int `json:"http_packets"`
		}{
			SYNPackets:  msg.SYNPackets,
			TCPPackets:  msg.TotalTCPPackets,
			UDPPackets:  msg.UDPPackets,
			ICMPPackets: msg.ICMPPackets,
			HTTPPackets: msg.HTTPPackets,
		}

	case types.AttackLog:
		wsMessage.Type = "attack"
		wsMessage.Data = msg

	case map[string]interface{}:
		// Handle raw map messages
		if typ, ok := msg["type"].(string); ok {
			wsMessage.Type = typ
			wsMessage.Data = msg["data"]
		} else {
			log.Printf("[ERROR] Message map missing 'type' field: %+v", msg)
			return
		}

	default:
		log.Printf("[ERROR] Unknown message type: %T", message)
		return
	}

	data, err := json.Marshal(wsMessage)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal websocket message: %v", err)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Use a timeout for each write
	deadline := time.Now().Add(5 * time.Second)
	for client := range h.clients {
		if err := client.SetWriteDeadline(deadline); err != nil {
			log.Printf("[ERROR] Failed to set write deadline: %v", err)
			client.Close()
			delete(h.clients, client)
			continue
		}

		if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("[ERROR] WebSocket write error: %v", err)
			client.Close()
			delete(h.clients, client)
		}
	}
}

func (h *WebSocketHub) BroadcastAttack(attack types.AttackLog) {
	h.UpdateThreatStats(&attack)
	h.broadcast <- attack
}

func (h *WebSocketHub) BroadcastStats(stats types.TrafficStats) {
	h.broadcast <- stats
}

func (h *WebSocketHub) UpdateThreatStats(attack *types.AttackLog) {
	h.statsMu.Lock()
	defer h.statsMu.Unlock()

	key := attack.Protocol
	if stat, exists := h.threatStats[key]; exists {
		stat.Count++
		if attack.Mitigated {
			stat.Mitigated++
		} else {
			stat.Active++
		}

		// Update attacks by type
		if stat.AttacksByType == nil {
			stat.AttacksByType = make(map[string]int)
		}
		stat.AttacksByType[attack.Description]++

		timestamp, err := time.Parse(time.RFC3339, attack.Timestamp)
		if err != nil {
			log.Printf("Error parsing timestamp: %v", err)
			return
		}
		if timestamp.After(stat.LastSeen) {
			stat.LastSeen = timestamp
		}
	} else {
		timestamp, err := time.Parse(time.RFC3339, attack.Timestamp)
		if err != nil {
			log.Printf("Error parsing timestamp: %v", err)
			return
		}
		h.threatStats[key] = &ThreatSummary{
			Protocol:  key,
			Count:     1,
			Severity:  attack.Severity,
			Mitigated: boolToInt(attack.Mitigated),
			Active:    boolToInt(!attack.Mitigated),
			LastSeen:  timestamp,
			AttacksByType: map[string]int{
				attack.Description: 1,
			},
		}
	}

	// Broadcast updated stats
	h.broadcastMessage(map[string]interface{}{
		"type": "threat_stats",
		"data": h.threatStats,
	})
}

func (h *WebSocketHub) broadcastThreatSummary() {
	h.statsMu.RLock()
	summary := make([]ThreatSummary, 0, len(h.threatStats))
	for _, stat := range h.threatStats {
		summary = append(summary, *stat)
	}
	h.statsMu.RUnlock()

	h.broadcastMessage(map[string]interface{}{
		"type":      "threat_summary",
		"data":      summary,
		"timestamp": time.Now().Unix(),
	})
}

func (h *WebSocketHub) Shutdown() {
	log.Println("Initiating WebSocket hub shutdown...")

	// Signal shutdown
	close(h.done)

	// Wait briefly for clients to disconnect
	time.Sleep(100 * time.Millisecond)

	// Force close any remaining clients
	h.closeAllConnections()

	log.Printf("WebSocket hub shutdown complete, disconnected %d clients", len(h.clients))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
