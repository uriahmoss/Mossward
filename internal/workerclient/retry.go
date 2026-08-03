package workerclient

import (
	cryptorand "crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maximumJitterPercent = 100

type RetryPolicy struct {
	InitialDelay  time.Duration
	MaximumDelay  time.Duration
	JitterPercent int
}

type RetryScheduler struct {
	policy RetryPolicy
	random func(int64) (int64, error)
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{InitialDelay: 2 * time.Second, MaximumDelay: 2 * time.Minute, JitterPercent: 20}
}

func NewRetryScheduler(policy RetryPolicy) (*RetryScheduler, error) {
	if err := validateRetryPolicy(policy); err != nil {
		return nil, err
	}
	return &RetryScheduler{policy: policy, random: secureRandomInt63n}, nil
}

func validateRetryPolicy(policy RetryPolicy) error {
	if policy.InitialDelay <= 0 || policy.MaximumDelay < policy.InitialDelay || policy.JitterPercent < 0 || policy.JitterPercent > maximumJitterPercent {
		return errors.New("scanner-worker retry policy is invalid")
	}
	return nil
}

func (s *RetryScheduler) Delay(consecutiveFailures int, retryAfter time.Duration) (time.Duration, error) {
	if consecutiveFailures < 0 || retryAfter < 0 {
		return 0, errors.New("scanner-worker retry state is invalid")
	}
	delay := s.exponentialDelay(consecutiveFailures)
	if retryAfter > delay {
		delay = retryAfter
	}
	if delay >= s.policy.MaximumDelay || s.policy.JitterPercent == 0 {
		return minDuration(delay, s.policy.MaximumDelay), nil
	}
	jitterLimit := int64(delay) * int64(s.policy.JitterPercent) / percentageScale
	if jitterLimit < 1 {
		return delay, nil
	}
	jitter, err := s.random(jitterLimit + 1)
	if err != nil {
		return 0, err
	}
	return minDuration(delay+time.Duration(jitter), s.policy.MaximumDelay), nil
}

func (s *RetryScheduler) exponentialDelay(failures int) time.Duration {
	delay := s.policy.InitialDelay
	for attempt := 1; attempt < failures && delay < s.policy.MaximumDelay; attempt++ {
		if delay > s.policy.MaximumDelay/2 {
			return s.policy.MaximumDelay
		}
		delay *= 2
	}
	return minDuration(delay, s.policy.MaximumDelay)
}

func secureRandomInt63n(maximum int64) (int64, error) {
	value, err := cryptorand.Int(cryptorand.Reader, big.NewInt(maximum))
	if err != nil {
		return 0, err
	}
	return value.Int64(), nil
}

func ParseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds > int64((time.Duration(1<<63-1))/time.Second) {
			return time.Duration(1<<63 - 1)
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
