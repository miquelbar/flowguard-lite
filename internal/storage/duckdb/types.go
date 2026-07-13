package duckdb

import "github.com/miquelbar/flowguard-lite/internal/storage"

const (
	SeverityCritical = storage.SeverityCritical
	SeverityHigh     = storage.SeverityHigh
	SeverityMedium   = storage.SeverityMedium
	SeverityLow      = storage.SeverityLow

	AnomalyStatusActive       = storage.AnomalyStatusActive
	AnomalyStatusAcknowledged = storage.AnomalyStatusAcknowledged
	AnomalyStatusSilenced     = storage.AnomalyStatusSilenced

	PolicyScopeGlobal    = storage.PolicyScopeGlobal
	PolicyScopeIP        = storage.PolicyScopeIP
	PolicyScopeSubnet    = storage.PolicyScopeSubnet
	PolicyScopeAlertType = storage.PolicyScopeAlertType

	NotificationScopeGlobal = storage.NotificationScopeGlobal
	NotificationScopeIP     = storage.NotificationScopeIP
	NotificationScopeSubnet = storage.NotificationScopeSubnet

	NotificationChannelWebhook  = storage.NotificationChannelWebhook
	NotificationChannelSlack    = storage.NotificationChannelSlack
	NotificationChannelTelegram = storage.NotificationChannelTelegram
)

type Device = storage.Device
type DeviceBaseline = storage.DeviceBaseline
type Anomaly = storage.Anomaly
type Policy = storage.Policy
type AuditLog = storage.AuditLog
type NotificationRule = storage.NotificationRule
type NotificationLog = storage.NotificationLog
type DeviceBaselineSample = storage.DeviceBaselineSample
type FlowHistoryResult = storage.FlowHistoryResult
type UniFiEvent = storage.UniFiEvent

func boolToInt(b bool) int {

	if b {
		return 1
	}
	return 0
}
