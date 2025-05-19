package detection

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snapLen     = 131072
	promiscuous = true
	timeout     = 30 * time.Millisecond
)

func CapturePackets(ctx context.Context, iface string, analyzer *Analyzer) error {
	handle, err := pcap.OpenLive(iface, snapLen, promiscuous, timeout)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", iface, err)
	}
	defer handle.Close()

	filter := "tcp or udp or icmp"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("Warning: Failed to set BPF filter '%s': %v", filter, err)
	} else {
		log.Printf("Applied BPF filter: %s", filter)
	}

	log.Printf("Started packet capture on interface: %s", iface)

	stats, err := handle.Stats()
	if err != nil {
		log.Printf("Warning: Failed to get initial interface stats: %v", err)
	} else {
		log.Printf("Initial interface stats: %d packets received, %d packets dropped", stats.PacketsReceived, stats.PacketsDropped)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packetSource.DecodeStreamsAsDatagrams = true

	statsStruct := &packetStats{
		startTime: time.Now(),
		iface:     iface,
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logFinalStats(statsStruct)
			return nil
		case <-ticker.C:
			logStats(statsStruct)
			if handleStats, err := handle.Stats(); err == nil {
				log.Printf("Interface %s stats: %d packets received, %d packets dropped", iface, handleStats.PacketsReceived, handleStats.PacketsDropped)
			}
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				if err == pcap.NextErrorTimeoutExpired {
					continue
				}
				logFinalStats(statsStruct)
				return fmt.Errorf("packet capture error: %v", err)
			}
			if packet == nil {
				log.Printf("Warning: Received nil packet on interface %s", iface)
				continue
			}

			statsStruct.packetsProcessed++
			// Log raw packet data for debugging
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				log.Printf("Captured packet - SrcIP: %s, DstIP: %s, Protocol: %s", ip.SrcIP, ip.DstIP, ip.Protocol)
			}
			if err := analyzer.ProcessPacket(packet); err != nil {
				log.Printf("Error processing packet: %v", err)
				statsStruct.packetsDropped++
			}
		}
	}
}

type packetStats struct {
	startTime        time.Time
	iface            string
	packetsProcessed uint64
	packetsDropped   uint64
}

func logStats(stats *packetStats) {
	duration := time.Since(stats.startTime)
	rate := float64(stats.packetsProcessed) / duration.Seconds()
	log.Printf("Interface %s - Processed: %d packets (%.2f/sec), Dropped: %d packets", stats.iface, stats.packetsProcessed, rate, stats.packetsDropped)
}

func logFinalStats(stats *packetStats) {
	duration := time.Since(stats.startTime)
	rate := float64(stats.packetsProcessed) / duration.Seconds()
	log.Printf("Stopping capture on %s - Final stats - Processed: %d packets (%.2f/sec), Dropped: %d", stats.iface, stats.packetsProcessed, rate, stats.packetsDropped)
}
