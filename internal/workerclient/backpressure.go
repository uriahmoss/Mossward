package workerclient

import (
	"errors"
	"math"
)

const percentageScale = 100

type OutboxPressure string

const (
	OutboxPressureNormal   OutboxPressure = "normal"
	OutboxPressureElevated OutboxPressure = "elevated"
	OutboxPressureCritical OutboxPressure = "critical"
	OutboxPressureFull     OutboxPressure = "full"
)

type BackpressurePolicy struct {
	PausePollingAtPercent int
	CriticalAtPercent     int
}

type BackpressureState struct {
	Pressure       OutboxPressure
	UsagePercent   int
	AcceptNewJobs  bool
	ForwardPending bool
}

func DefaultBackpressurePolicy() BackpressurePolicy {
	return BackpressurePolicy{PausePollingAtPercent: 75, CriticalAtPercent: 90}
}

func (o *Outbox) Backpressure(policy BackpressurePolicy) (BackpressureState, error) {
	if policy.PausePollingAtPercent < 1 || policy.CriticalAtPercent <= policy.PausePollingAtPercent || policy.CriticalAtPercent > percentageScale {
		return BackpressureState{}, errors.New("scanner-worker backpressure thresholds are invalid")
	}
	stats, err := o.Stats()
	if err != nil {
		return BackpressureState{}, err
	}
	usage := maximumPercentage(stats.Items, o.limits.MaxItems, stats.Bytes, o.limits.MaxBytes)
	pressure := OutboxPressureNormal
	if usage >= percentageScale {
		pressure = OutboxPressureFull
	} else if usage >= policy.CriticalAtPercent {
		pressure = OutboxPressureCritical
	} else if usage >= policy.PausePollingAtPercent {
		pressure = OutboxPressureElevated
	}
	return BackpressureState{Pressure: pressure, UsagePercent: usage,
		AcceptNewJobs: pressure == OutboxPressureNormal, ForwardPending: stats.Items > 0}, nil
}

func maximumPercentage(items, maximumItems int, bytes, maximumBytes int64) int {
	itemPercent := roundedUpPercent(int64(items), int64(maximumItems))
	bytePercent := roundedUpPercent(bytes, maximumBytes)
	if bytePercent > itemPercent {
		return bytePercent
	}
	return itemPercent
}

func roundedUpPercent(value, maximum int64) int {
	if value <= 0 {
		return 0
	}
	return int(math.Ceil(float64(value) * percentageScale / float64(maximum)))
}
