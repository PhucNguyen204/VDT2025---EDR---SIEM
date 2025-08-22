package engine

import (
	"sync/atomic"
	"time"
)

// GetStats returns current engine statistics
func (e *Engine) GetStats() Stats {
	uptime := time.Since(e.startTime).String()
	
	return Stats{
		EventsProcessed: atomic.LoadUint64(&e.eventsProcessed),
		AlertsGenerated: atomic.LoadUint64(&e.alertsGenerated),
		RulesLoaded:     atomic.LoadUint64(&e.rulesLoaded),
		Uptime:          uptime,
	}
}
