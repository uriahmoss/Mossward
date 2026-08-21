package relaywindow

import (
	"errors"
	"strings"
	"time"

	"mossward/internal/model"
)

const (
	minutesPerDay      = 24 * 60
	maximumNameBytes   = 200
	maximumIDBytes     = 200
	maximumReasonBytes = 500
)

func Validate(window model.RelayUploadWindow) error {
	if strings.TrimSpace(window.Name) == "" || len(window.Name) > maximumNameBytes || strings.TrimSpace(window.TargetID) == "" || len(window.TargetID) > maximumIDBytes ||
		len(window.Reason) > maximumReasonBytes || window.StartMinute < 0 || window.StartMinute >= minutesPerDay || window.EndMinute < 0 || window.EndMinute >= minutesPerDay || window.StartMinute == window.EndMinute {
		return errors.New("relay upload window settings are invalid")
	}
	if window.TargetType != model.MaintenanceTargetEndpoint && window.TargetType != model.MaintenanceTargetGroup {
		return errors.New("relay upload window target is invalid")
	}
	if _, err := time.LoadLocation(window.Timezone); err != nil {
		return errors.New("relay upload window timezone must be a valid IANA timezone")
	}
	if len(window.Days) == 0 || len(window.Days) > 7 {
		return errors.New("relay upload window requires one or more unique weekdays")
	}
	seen := map[time.Weekday]bool{}
	for _, day := range window.Days {
		if day < time.Sunday || day > time.Saturday || seen[day] {
			return errors.New("relay upload window weekdays are invalid")
		}
		seen[day] = true
	}
	return nil
}

func Open(window model.RelayUploadWindow, now time.Time) (bool, error) {
	if err := Validate(window); err != nil {
		return false, err
	}
	if !window.Enabled {
		return false, nil
	}
	location, _ := time.LoadLocation(window.Timezone)
	local := now.In(location)
	minute := local.Hour()*60 + local.Minute()
	if window.StartMinute < window.EndMinute {
		return containsDay(window.Days, local.Weekday()) && minute >= window.StartMinute && minute < window.EndMinute, nil
	}
	if minute >= window.StartMinute {
		return containsDay(window.Days, local.Weekday()), nil
	}
	return minute < window.EndMinute && containsDay(window.Days, previousDay(local.Weekday())), nil
}

func containsDay(days []time.Weekday, wanted time.Weekday) bool {
	for _, day := range days {
		if day == wanted {
			return true
		}
	}
	return false
}

func previousDay(day time.Weekday) time.Weekday {
	if day == time.Sunday {
		return time.Saturday
	}
	return day - 1
}
