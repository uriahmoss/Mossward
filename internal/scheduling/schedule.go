package scheduling

import (
	"errors"
	"fmt"
	"github.com/robfig/cron/v3"
	"mossward/internal/model"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
)

func Prepare(policy *model.ReusableScanPolicy, now time.Time) error {
	policy.ScheduleKind = strings.ToLower(strings.TrimSpace(policy.ScheduleKind))
	if policy.ScheduleKind == "" {
		policy.ScheduleKind = "manual"
	}
	policy.ScheduleTimezone = strings.TrimSpace(policy.ScheduleTimezone)
	if policy.ScheduleTimezone == "" {
		policy.ScheduleTimezone = "UTC"
	}
	location, err := time.LoadLocation(policy.ScheduleTimezone)
	if err != nil {
		return errors.New("schedule timezone is invalid")
	}
	if err := validateWindow(policy.WindowStart, policy.WindowEnd); err != nil {
		return err
	}
	if policy.LongRunAlertSeconds < 0 {
		return errors.New("long-run alert threshold cannot be negative")
	}
	if policy.ScheduleKind == "manual" {
		policy.NextRunAt = nil
		policy.ScheduleExpression = ""
		return nil
	}
	next, err := Next(*policy, now, location)
	if err != nil {
		return err
	}
	policy.NextRunAt = &next
	return nil
}
func Next(policy model.ReusableScanPolicy, after time.Time, location *time.Location) (time.Time, error) {
	expression := strings.TrimSpace(policy.ScheduleExpression)
	switch policy.ScheduleKind {
	case "once":
		value, err := time.Parse(time.RFC3339, expression)
		if err != nil || !value.After(after) {
			return time.Time{}, errors.New("one-time schedule must be a future RFC3339 timestamp")
		}
		return value.UTC(), nil
	case "daily":
		hour, minute, err := parseClock(expression)
		if err != nil {
			return time.Time{}, err
		}
		expression = fmt.Sprintf("%d %d * * *", minute, hour)
	case "weekly":
		parts := strings.Fields(expression)
		if len(parts) != 2 {
			return time.Time{}, errors.New("weekly schedule must use 'days HH:MM'")
		}
		hour, minute, err := parseClock(parts[1])
		if err != nil {
			return time.Time{}, err
		}
		expression = fmt.Sprintf("%d %d * * %s", minute, hour, parts[0])
	case "cron":
	default:
		return time.Time{}, errors.New("schedule kind must be manual, once, daily, weekly, or cron")
	}
	schedule, err := cron.ParseStandard(expression)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid schedule expression: %w", err)
	}
	return schedule.Next(after.In(location)).UTC(), nil
}
func Window(policy model.ReusableScanPolicy, now time.Time) (bool, *time.Time, error) {
	location, err := time.LoadLocation(policy.ScheduleTimezone)
	if err != nil {
		return false, nil, err
	}
	if policy.WindowStart == "" {
		return true, nil, nil
	}
	startHour, startMinute, _ := parseClock(policy.WindowStart)
	endHour, endMinute, _ := parseClock(policy.WindowEnd)
	local := now.In(location)
	start := time.Date(local.Year(), local.Month(), local.Day(), startHour, startMinute, 0, 0, location)
	end := time.Date(local.Year(), local.Month(), local.Day(), endHour, endMinute, 0, 0, location)
	if !end.After(start) {
		if local.Before(end) {
			start = start.AddDate(0, 0, -1)
		} else {
			end = end.AddDate(0, 0, 1)
		}
	}
	inside := !local.Before(start) && local.Before(end)
	endUTC := end.UTC()
	return inside, &endUTC, nil
}
func parseClock(value string) (int, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("time must use HH:MM")
	}
	hour, hourErr := strconv.Atoi(parts[0])
	minute, minuteErr := strconv.Atoi(parts[1])
	if hourErr != nil || minuteErr != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, errors.New("time must use HH:MM")
	}
	return hour, minute, nil
}
func validateWindow(start, end string) error {
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)
	if (start == "") != (end == "") {
		return errors.New("maintenance window requires both start and end times")
	}
	if start == "" {
		return nil
	}
	if _, _, err := parseClock(start); err != nil {
		return fmt.Errorf("invalid window start: %w", err)
	}
	if _, _, err := parseClock(end); err != nil {
		return fmt.Errorf("invalid window end: %w", err)
	}
	if start == end {
		return errors.New("maintenance window start and end must differ")
	}
	return nil
}
