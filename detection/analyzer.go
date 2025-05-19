package detection

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"intrualert/mitigation"
	"intrualert/storage"
	"intrualert/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

type Analyzer struct {
	cfg                *types.Config
	signatures         []types.Signature
	wafClient          *mitigation.WAFClient
	store              *storage.Storage
	broadcaster        types.Broadcaster
	stats              map[string]int
	ipStats            map[string]*IPStats
	mu                 sync.Mutex
	workers            int
	packetChan         chan gopacket.Packet
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
	isClosing          bool
	lastStatsBroadcast time.Time
}

type IPStats struct {
	// Keeping only used fields
	stats map[string]int
}

func NewAnalyzer(cfg *types.Config, signatures []types.Signature, wafClient *mitigation.WAFClient, store *storage.Storage, broadcaster types.Broadcaster) (*Analyzer, error) {
	ctx, cancel := context.WithCancel(context.Background())
	a := &Analyzer{
		cfg:         cfg,
		signatures:  signatures,
		wafClient:   wafClient,
		store:       store,
		broadcaster: broadcaster,
		stats:       make(map[string]int),
		ipStats:     make(map[string]*IPStats),
		workers:     8,
		packetChan:  make(chan gopacket.Packet, 100000),
		ctx:         ctx,
		cancel:      cancel,
	}

	log.Printf("Starting %d analyzer workers", a.workers)
	for i := 0; i < a.workers; i++ {
		go a.worker(i)
	}

	go a.storeStatsPeriodically()
	return a, nil
}

func (a *Analyzer) worker(id int) {
	a.wg.Add(1)
	defer a.wg.Done()

	log.Printf("Worker %d started", id)
	for {
		select {
		case <-a.ctx.Done():
			log.Printf("Worker %d shutting down", id)
			return
		case packet, ok := <-a.packetChan:
			if !ok {
				log.Printf("Worker %d channel closed", id)
				return
			}
			if err := a.processPacket(packet); err != nil {
				log.Printf("Worker %d error processing packet: %v", id, err)
			}
		}
	}
}

func (a *Analyzer) ProcessPacket(packet gopacket.Packet) error {
	// Don't accept packets if shutting down
	if a.isClosing {
		return nil
	}

	select {
	case a.packetChan <- packet:
		return nil
	case <-a.ctx.Done():
		return a.ctx.Err()
	default:
		log.Println("Warning: Packet channel full, dropping packet")
		return nil
	}
}

func (a *Analyzer) processPacket(packet gopacket.Packet) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Process TCP packets
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			a.stats["syn"]++
			// Check for SYN flood
			if a.stats["syn"] > a.cfg.SYNFloodThreshold {
				attack := a.createAttackLog(
					uuid.New().String(),
					"SYN Flood Attack",
					"TCP",
					"High",
					packet)
				go a.storeAndBroadcastAttack(attack)
				// Add mitigation call
				go a.mitigate(packet, "SYN Flood Attack")
			}
		}
		a.stats["tcp"]++
	}

	// Process UDP packets
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		a.stats["udp"]++
		if a.stats["udp"] > a.cfg.UDPFloodThreshold {
			attack := a.createAttackLog(
				uuid.New().String(),
				"UDP Flood Attack",
				"UDP",
				"High",
				packet)
			go a.storeAndBroadcastAttack(attack)
			// Add mitigation call
			go a.mitigate(packet, "UDP Flood Attack")
		}
	}

	// Process ICMP packets
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		a.stats["icmp"]++
		if a.stats["icmp"] > a.cfg.ICMPFloodThreshold {
			attack := a.createAttackLog(
				uuid.New().String(),
				"ICMP Flood Attack",
				"ICMP",
				"High",
				packet)
			go a.storeAndBroadcastAttack(attack)
			// Add mitigation call
			go a.mitigate(packet, "ICMP Flood Attack")
		}
	}

	// Process HTTP packets (based on TCP port 80/443)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.DstPort == 80 || tcp.DstPort == 443 {
			a.stats["http"]++
			// Check HTTP flood
			if a.stats["http"] > a.cfg.HTTPFloodThreshold {
				attack := a.createAttackLog(
					uuid.New().String(),
					"HTTP Flood Attack",
					"HTTP",
					"High",
					packet)
				go a.storeAndBroadcastAttack(attack)
			}
		}
	}

	// Broadcast stats every second
	if time.Since(a.lastStatsBroadcast) > time.Second {
		stats := a.GetStatistics()
		if a.broadcaster != nil {
			a.broadcaster.BroadcastStats(stats)
		}
		a.lastStatsBroadcast = time.Now()

		// Store stats periodically
		if err := a.storeTrafficStats(); err != nil {
			log.Printf("Failed to store traffic stats: %v", err)
		}
	}

	return nil
}

func (a *Analyzer) storeAndBroadcastAttack(attack *types.AttackLog) {
	if err := a.store.StoreAttack(*attack); err != nil {
		log.Printf("Failed to store attack: %v", err)
		return
	}

	// Update IP stats
	srcIP := attack.SourceIP
	if _, exists := a.ipStats[srcIP]; !exists {
		a.ipStats[srcIP] = &IPStats{
			stats: make(map[string]int),
		}
	}
	a.ipStats[srcIP].stats[attack.Protocol]++

	if a.broadcaster != nil {
		a.broadcaster.BroadcastAttack(*attack)
	}
}

func (a *Analyzer) createAttackLog(id, description, protocol, severity string, packet gopacket.Packet) *types.AttackLog {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)

	return &types.AttackLog{
		AttackID:      id,
		Timestamp:     time.Now().Format(time.RFC3339),
		SourceIP:      ip.SrcIP.String(),
		DestinationIP: ip.DstIP.String(),
		Protocol:      protocol,
		Description:   description,
		Severity:      severity,
		Mitigated:     false,
	}
}

func (a *Analyzer) storeStatsPeriodically() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			log.Println("Stopping periodic stats storage")
			return
		case <-ticker.C:
			if a.cfg.StorageEnabled {
				if err := a.storeTrafficStats(); err != nil {
					log.Printf("Failed to store traffic stats: %v", err)
				}
			}
		}
	}
}

func (a *Analyzer) storeTrafficStats() error {
	stats := a.GetStatistics()

	// Store stats in the database
	if err := a.store.StoreTrafficStats(stats); err != nil {
		return fmt.Errorf("failed to store traffic stats: %v", err)
	}

	log.Printf("Stored traffic stats: SYN=%d UDP=%d ICMP=%d HTTP=%d",
		stats.SYNPackets,
		stats.UDPPackets,
		stats.ICMPPackets,
		stats.HTTPPackets)

	return nil
}

func (a *Analyzer) mitigate(packet gopacket.Packet, reason string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := a.wafClient.BlockIP(ctx, ip.SrcIP.String(), reason); err != nil {
		log.Printf("Failed to block IP %s: %v", ip.SrcIP, err)
	} else {
		log.Printf("Blocked IP %s: %s", ip.SrcIP, reason)
	}
}

func (a *Analyzer) GetStatistics() types.TrafficStats {
	return types.TrafficStats{
		Timestamp:       time.Now().Format(time.RFC3339),
		SYNPackets:      a.stats["syn"],
		TotalTCPPackets: a.stats["tcp"],
		UDPPackets:      a.stats["udp"],
		ICMPPackets:     a.stats["icmp"],
		HTTPPackets:     a.stats["http"],
	}
}

func (a *Analyzer) Shutdown() {
	a.mu.Lock()
	a.isClosing = true
	log.Printf("Analyzer shutdown: Processed %d SYN, %d UDP, %d ICMP, %d HTTP packets",
		a.stats["syn"], a.stats["udp"], a.stats["icmp"], a.stats["http"])
	a.mu.Unlock()

	// Signal shutdown to all workers
	a.cancel()

	// Wait for workers to finish
	a.wg.Wait()

	// Only close channel after workers are done
	close(a.packetChan)
}
