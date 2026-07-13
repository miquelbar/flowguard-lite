package storage

import (
	"fmt"
	"strings"
	"time"
)

// IsTimeInQuietHours reports whether t falls inside the configured quiet-hours window.
func IsTimeInQuietHours(t time.Time, startStr, endStr string) bool {
	if startStr == "" || endStr == "" {
		return false
	}
	startParts := strings.Split(startStr, ":")
	endParts := strings.Split(endStr, ":")
	if len(startParts) != 2 || len(endParts) != 2 {
		return false
	}

	var startH, startM, endH, endM int
	fmt.Sscanf(startStr, "%d:%d", &startH, &startM)
	fmt.Sscanf(endStr, "%d:%d", &endH, &endM)

	curH, curM, _ := t.Clock()
	startVal := startH*60 + startM
	endVal := endH*60 + endM
	curVal := curH*60 + curM

	if startVal <= endVal {
		return curVal >= startVal && curVal <= endVal
	}
	return curVal >= startVal || curVal <= endVal
}
