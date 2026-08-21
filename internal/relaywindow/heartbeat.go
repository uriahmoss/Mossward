package relaywindow

import (
	"time"

	"mossward/internal/model"
)

type HeartbeatSuppression struct {
	Suppressed  bool      `json:"suppressed"`
	Reason      string    `json:"reason"`
	WindowIDs   []string  `json:"window_ids"`
	LastCloseAt time.Time `json:"last_close_at,omitempty"`
}

func HeartbeatAlertSuppression(windows []model.RelayUploadWindow, policy model.ResolvedDelayedHeartbeatPolicy, now time.Time) (HeartbeatSuppression, error) {
	result := HeartbeatSuppression{Reason: "delayed_heartbeats_not_allowed", WindowIDs: []string{}}
	if !policy.AllowDelayedHeartbeats {
		return result, nil
	}
	result.Reason = "outside_post_window_grace"
	var latestClose time.Time
	for _, window := range windows {
		if err := Validate(window); err != nil {
			return HeartbeatSuppression{}, err
		}
		if !window.Enabled {
			continue
		}
		open, _ := Open(window, now)
		if open {
			result.Suppressed, result.Reason = true, "upload_window_open"
			result.WindowIDs = append(result.WindowIDs, window.ID)
		}
		closedAt := mostRecentClose(window, now)
		if closedAt.After(latestClose) {
			latestClose = closedAt
		}
	}
	if result.Suppressed {
		return result, nil
	}
	result.LastCloseAt = latestClose
	grace := time.Duration(policy.PostWindowGraceMinutes) * time.Minute
	if !latestClose.IsZero() && grace > 0 && !now.After(latestClose.Add(grace)) {
		result.Suppressed, result.Reason = true, "post_window_grace"
	}
	return result, nil
}

func mostRecentClose(window model.RelayUploadWindow, now time.Time) time.Time {
	location, _ := time.LoadLocation(window.Timezone)
	localNow := now.In(location)
	latest := time.Time{}
	for offset := 0; offset <= 7; offset++ {
		startDate := localNow.AddDate(0, 0, -offset)
		if !containsDay(window.Days, startDate.Weekday()) {
			continue
		}
		endDate := startDate
		if window.StartMinute > window.EndMinute {
			endDate = endDate.AddDate(0, 0, 1)
		}
		closedAt := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), window.EndMinute/60, window.EndMinute%60, 0, 0, location)
		if closedAt.After(now) || !closedAt.After(latest) {
			continue
		}
		latest = closedAt
	}
	return latest
}
