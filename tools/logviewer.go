package tools

import (
	"fmt"
	"log"
	"os"
	"strings"
)

func ViewLogs(logFile string) error {
	data, err := os.ReadFile(logFile)
	if err != nil {
		log.Printf("Failed to read log file %s: %v", logFile, err)
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line != "" {
			fmt.Println(line)
		}
	}
	return nil
}
