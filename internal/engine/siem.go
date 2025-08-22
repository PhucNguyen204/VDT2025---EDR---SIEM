package engine

import (
	"time"

	"github.com/sirupsen/logrus"
)

// siemForwarder forwards alerts to SIEM in batches
func (e *Engine) siemForwarder() {
	defer e.wg.Done()

	ticker := time.NewTicker(30 * time.Second) // Batch every 30 seconds
	defer ticker.Stop()

	var alertBatch []*Alert

	for {
		select {
		case <-ticker.C:
			if len(alertBatch) > 0 {
				e.forwardToSIEM(alertBatch)
				alertBatch = nil
			}

		case <-e.ctx.Done():
			// Forward remaining alerts before shutdown
			if len(alertBatch) > 0 {
				e.forwardToSIEM(alertBatch)
			}
			return
		}
	}
}

// forwardToSIEM sends alerts to external SIEM system
func (e *Engine) forwardToSIEM(alerts []*Alert) {
	if e.config.SIEMEndpoint == "" {
		return // No SIEM configured
	}

	logrus.WithField("count", len(alerts)).Info("Forwarding alerts to SIEM")
	// TODO: Implement actual SIEM forwarding logic
	// This could be HTTP POST, syslog, Kafka, etc.
}
