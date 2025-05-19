package main

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	for _, device := range devices {
		fmt.Printf("Name: %s\nDescription: %s\n\n", device.Name, device.Description)
	}
}
