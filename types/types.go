package types

import (
	"encoding/json"
	"os"
	"time"
)

// WAFConfig holds AWS WAF configuration
type WAFConfig struct {
	IPSetName  string `json:"ip_set_name"`
	IPSetID    string `json:"ip_set_id"`
	Scope      string `json:"scope"`
	ARN        string `json:"arn"`
	WebACLName string `json:"web_acl_name"`
	WebACLID   string `json:"web_acl_id"`
	WebACLARN  string `json:"web_acl_arn"`
}

// Config holds the application configuration
type Config struct {
	Interfaces           []string  `json:"interfaces"`
	Port                 int       `json:"port"`
	SYNFloodThreshold    int       `json:"syn_flood_threshold"`
	UDPFloodThreshold    int       `json:"udp_flood_threshold"`
	ICMPFloodThreshold   int       `json:"icmp_flood_threshold"`
	HTTPFloodThreshold   int       `json:"http_flood_threshold"`
	SignatureFile        string    `json:"signature_file"`
	Region               string    `json:"region"`
	MitigationEnabled    bool      `json:"mitigation_enabled"`
	StorageEnabled       bool      `json:"storage_enabled"`
	DynamoDBAttackTable  string    `json:"dynamodb_attack_table,omitempty"`
	DynamoDBUserTable    string    `json:"dynamodb_user_table,omitempty"`
	DynamoDBTrafficTable string    `json:"dynamodb_traffic_table,omitempty"`
	SessionSecret        string    `json:"session_secret"`
	WAF                  WAFConfig `json:"waf"`
}

// Signature defines a rule for detecting malicious patterns
type Signature struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Threshold   int    `json:"threshold"`
	Window      int    `json:"window"`
}

// AttackLog represents a detected attack
type AttackLog struct {
	AttackID      string `json:"attack_id" dynamodbav:"AttackID"`
	Timestamp     string `json:"timestamp" dynamodbav:"Timestamp"`
	Protocol      string `json:"protocol" dynamodbav:"Protocol"`
	SourceIP      string `json:"source_ip" dynamodbav:"SourceIP"`
	DestinationIP string `json:"destination_ip" dynamodbav:"DestinationIP"`
	Description   string `json:"description" dynamodbav:"Description"`
	Severity      string `json:"severity" dynamodbav:"Severity"`
	Mitigated     bool   `json:"mitigated" dynamodbav:"Mitigated"`
}

// TrafficStats holds network traffic statistics
type TrafficStats struct {
	Timestamp       string `json:"timestamp" dynamodbav:"Timestamp"`
	SYNPackets      int    `json:"syn_packets" dynamodbav:"SYNPackets"`
	TotalTCPPackets int    `json:"tcp_packets" dynamodbav:"TCPPackets"`
	UDPPackets      int    `json:"udp_packets" dynamodbav:"UDPPackets"`
	ICMPPackets     int    `json:"icmp_packets" dynamodbav:"ICMPPackets"`
	HTTPPackets     int    `json:"http_packets" dynamodbav:"HTTPPackets"`
}

// ThreatSummary represents aggregated attack statistics
type ThreatSummary struct {
	Protocol  string    `json:"protocol"`
	Count     int       `json:"count"`
	Severity  string    `json:"severity"`
	Mitigated int       `json:"mitigated"`
	Active    int       `json:"active"`
	LastSeen  time.Time `json:"last_seen"`
}

// User represents a user account
type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Broadcaster interface for broadcasting events
type Broadcaster interface {
	BroadcastAttack(attack AttackLog)
	BroadcastStats(stats TrafficStats)
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadSignatures loads signatures from a JSON file
func LoadSignatures(path string) ([]Signature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var signatures []Signature
	if err := json.Unmarshal(data, &signatures); err != nil {
		return nil, err
	}
	return signatures, nil
}
