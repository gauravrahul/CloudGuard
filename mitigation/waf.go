package mitigation

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"intrualert/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"golang.org/x/time/rate"
)

type WAFClient struct {
	client      *wafv2.Client
	ipSetName   string
	ipSetID     string
	scope       waftypes.Scope
	arn         string
	webACLName  string
	webACLID    string
	webACLARN   string
	rateLimiter *rate.Limiter
	lockToken   string
	mu          sync.Mutex // Add mutex for thread safety
}

func NewWAFClient(cfg aws.Config, wafConfig types.WAFConfig) (*WAFClient, error) {
	if wafConfig.ARN == "" || wafConfig.WebACLARN == "" {
		return nil, fmt.Errorf("WAF ARN or WebACL ARN not configured")
	}

	scope := waftypes.ScopeRegional
	if wafConfig.Scope == "CLOUDFRONT" {
		scope = waftypes.ScopeCloudfront
	}

	client := wafv2.NewFromConfig(cfg)
	// More conservative rate limiting: 1 request per second
	rateLimiter := rate.NewLimiter(rate.Every(time.Second), 1)

	return &WAFClient{
		client:      client,
		ipSetName:   wafConfig.IPSetName,
		ipSetID:     wafConfig.IPSetID,
		scope:       scope,
		arn:         wafConfig.ARN,
		webACLName:  wafConfig.WebACLName,
		webACLID:    wafConfig.WebACLID,
		webACLARN:   wafConfig.WebACLARN,
		rateLimiter: rateLimiter,
	}, nil
}

func (c *WAFClient) Initialize(ctx context.Context) error {
	// Get current IP set to obtain lock token
	getInput := &wafv2.GetIPSetInput{
		Name:  aws.String(c.ipSetName),
		Scope: c.scope,
		Id:    aws.String(c.ipSetID),
	}

	result, err := c.client.GetIPSet(ctx, getInput)
	if err != nil {
		return fmt.Errorf("failed to get IP set %s: %w", c.ipSetName, err)
	}

	// Store the lock token
	c.lockToken = *result.LockToken
	log.Printf("Initialized WAF client with IP set %s", c.ipSetName)
	return nil
}

func (c *WAFClient) BlockIP(ctx context.Context, ip, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	log.Printf("[DEBUG] Attempting to block IP %s with WAF using IPSet %s", ip, c.ipSetName)

	// Format IP with CIDR notation if not present
	if !strings.Contains(ip, "/") {
		ip = ip + "/32"
	}

	// Get current IP set first
	ipSet, err := c.GetIPSet(ctx)
	if err != nil {
		return fmt.Errorf("failed to get IP set: %w", err)
	}

	// Combine existing addresses with new IP
	addresses := append(ipSet.IPSet.Addresses, ip)
	// Remove duplicates
	addresses = removeDuplicateIPs(addresses)

	// Use exponential backoff for retries
	backoff := time.Second
	maxRetries := 5

	for i := 0; i < maxRetries; i++ {
		// Wait for rate limiter
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limit wait failed: %w", err)
		}

		updateIPSetInput := &wafv2.UpdateIPSetInput{
			Name:      aws.String(c.ipSetName),
			Scope:     c.scope,
			Id:        aws.String(c.ipSetID),
			Addresses: addresses,
			LockToken: ipSet.LockToken,
		}

		result, err := c.client.UpdateIPSet(ctx, updateIPSetInput)
		if err == nil {
			// Update successful
			c.lockToken = *result.NextLockToken
			log.Printf("[INFO] Successfully blocked IP %s in WAF IPSet %s", ip, c.ipSetName)
			return nil
		}

		if strings.Contains(err.Error(), "WAFOptimisticLockException") {
			// Get fresh IP set data for next attempt
			ipSet, err = c.GetIPSet(ctx)
			if err != nil {
				return fmt.Errorf("failed to refresh IP set: %w", err)
			}
			time.Sleep(backoff)
			backoff *= 2 // Exponential backoff
			continue
		}

		// For other errors, return immediately
		return fmt.Errorf("failed to update IP set: %w", err)
	}

	return fmt.Errorf("failed to update IP set after %d retries", maxRetries)
}

func (w *WAFClient) GetIPSet(ctx context.Context) (*wafv2.GetIPSetOutput, error) {
	if err := w.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait failed: %w", err)
	}

	input := &wafv2.GetIPSetInput{
		Id:    aws.String(w.ipSetID),
		Name:  aws.String(w.ipSetName),
		Scope: w.scope,
	}

	return w.client.GetIPSet(ctx, input)
}

func (w *WAFClient) UpdateIPSet(ctx context.Context, addresses []string, lockToken *string) error {
	if err := w.rateLimiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limit wait failed: %w", err)
	}

	input := &wafv2.UpdateIPSetInput{
		Id:        aws.String(w.ipSetID),
		Name:      aws.String(w.ipSetName),
		Scope:     w.scope,
		Addresses: addresses,
		LockToken: lockToken,
	}

	_, err := w.client.UpdateIPSet(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update IP set: %w", err)
	}

	return nil
}

// Update the Cleanup method to use Wait instead of accessing channel directly
func (w *WAFClient) Cleanup(ctx context.Context) error {
	// Wait for rate limit
	if err := w.rateLimiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limit wait failed: %w", err)
	}

	// Get current IP set
	ipSet, err := w.GetIPSet(ctx)
	if err != nil {
		return fmt.Errorf("failed to get IP set: %w", err)
	}

	// Clear all IPs
	_, err = w.client.UpdateIPSet(ctx, &wafv2.UpdateIPSetInput{
		Name:      aws.String(w.ipSetName),
		Id:        aws.String(w.ipSetID),
		Scope:     w.scope,
		Addresses: []string{},
		LockToken: ipSet.LockToken,
	})

	if err != nil {
		return fmt.Errorf("failed to clean IP set: %w", err)
	}

	return nil
}

// Add helper function to remove duplicate IPs
func removeDuplicateIPs(ips []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}
	return result
}
