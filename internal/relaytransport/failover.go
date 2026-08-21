package relaytransport

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

type RouteKind string

const (
	RouteRelay  RouteKind = "relay"
	RouteDirect RouteKind = "direct"

	minimumObservationAge   = 10 * time.Second
	maximumObservationAge   = time.Hour
	maximumFailureThreshold = 10
	maximumFailoverRoutes   = 16
	maximumRouteIDLength    = 200
)

var ErrNoApprovedRoute = errors.New("no healthy approved relay route is available")

type ApprovedRoute struct {
	ID              string    `json:"id"`
	Kind            RouteKind `json:"kind"`
	RelayEndpointID string    `json:"relay_endpoint_id,omitempty"`
	Priority        int       `json:"priority"`
}

type FailoverPolicy struct {
	EndpointID        string          `json:"endpoint_id"`
	Routes            []ApprovedRoute `json:"routes"`
	FailureThreshold  int             `json:"failure_threshold"`
	ObservationMaxAge time.Duration   `json:"observation_max_age"`
}

type RouteAvailability struct {
	RouteID    string    `json:"route_id"`
	Healthy    bool      `json:"healthy"`
	ObservedAt time.Time `json:"observed_at"`
}

type RouteDecision struct {
	Route               ApprovedRoute `json:"route"`
	PreviousRouteID     string        `json:"previous_route_id,omitempty"`
	Reason              string        `json:"reason"`
	ConsecutiveFailures int           `json:"consecutive_failures"`
	SelectedAt          time.Time     `json:"selected_at"`
}

type FailoverController struct {
	mu                  sync.Mutex
	policy              FailoverPolicy
	activeRouteID       string
	consecutiveFailures int
}

func NewFailoverController(policy FailoverPolicy) (*FailoverController, error) {
	if err := validateFailoverPolicy(policy); err != nil {
		return nil, err
	}
	policy.Routes = append([]ApprovedRoute(nil), policy.Routes...)
	sort.Slice(policy.Routes, func(left, right int) bool {
		return policy.Routes[left].Priority < policy.Routes[right].Priority
	})
	return &FailoverController{policy: policy}, nil
}

func (c *FailoverController) Select(availability []RouteAvailability, now time.Time) (RouteDecision, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	health := availableRouteIDs(availability, c.policy.ObservationMaxAge, now)
	if c.activeRouteID != "" && c.consecutiveFailures < c.policy.FailureThreshold && health[c.activeRouteID] {
		decision, _ := c.decision(c.activeRouteID, c.activeRouteID, "active_route_healthy", now)
		return decision, nil
	}
	previous := c.activeRouteID
	for _, route := range c.policy.Routes {
		if route.ID == previous || !health[route.ID] {
			continue
		}
		c.activeRouteID = route.ID
		failures := c.consecutiveFailures
		c.consecutiveFailures = 0
		reason := "approved_initial_route"
		if previous != "" {
			reason = "approved_failover"
		}
		decision, _ := c.decision(route.ID, previous, reason, now)
		decision.ConsecutiveFailures = failures
		return decision, nil
	}
	return RouteDecision{}, ErrNoApprovedRoute
}

func (c *FailoverController) RecordDelivery(routeID string, succeeded bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if routeID == "" || routeID != c.activeRouteID {
		return errors.New("delivery result does not match the active approved route")
	}
	if succeeded {
		c.consecutiveFailures = 0
		return nil
	}
	if c.consecutiveFailures < c.policy.FailureThreshold {
		c.consecutiveFailures++
	}
	return nil
}

func (c *FailoverController) SelectApprovedRoute(routeID string, availability []RouteAvailability, now time.Time) (RouteDecision, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	health := availableRouteIDs(availability, c.policy.ObservationMaxAge, now)
	if !health[routeID] {
		return RouteDecision{}, ErrNoApprovedRoute
	}
	previous := c.activeRouteID
	decision, ok := c.decision(routeID, previous, "server_selected_approved_route", now)
	if !ok {
		return RouteDecision{}, ErrNoApprovedRoute
	}
	c.activeRouteID = routeID
	c.consecutiveFailures = 0
	return decision, nil
}

func (c *FailoverController) decision(routeID, previous, reason string, now time.Time) (RouteDecision, bool) {
	for _, route := range c.policy.Routes {
		if route.ID == routeID {
			return RouteDecision{Route: route, PreviousRouteID: previous, Reason: reason,
				ConsecutiveFailures: c.consecutiveFailures, SelectedAt: now.UTC()}, true
		}
	}
	return RouteDecision{}, false
}

func validateFailoverPolicy(policy FailoverPolicy) error {
	if strings.TrimSpace(policy.EndpointID) == "" || len(policy.EndpointID) > maximumRouteIDLength || len(policy.Routes) == 0 || len(policy.Routes) > maximumFailoverRoutes || policy.FailureThreshold < 1 || policy.FailureThreshold > maximumFailureThreshold ||
		policy.ObservationMaxAge < minimumObservationAge || policy.ObservationMaxAge > maximumObservationAge {
		return errors.New("relay failover policy is invalid")
	}
	ids := make(map[string]bool, len(policy.Routes))
	priorities := make(map[int]bool, len(policy.Routes))
	directRoutes := 0
	for _, route := range policy.Routes {
		if strings.TrimSpace(route.ID) == "" || len(route.ID) > maximumRouteIDLength || len(route.RelayEndpointID) > maximumRouteIDLength || route.Priority < 1 || ids[route.ID] || priorities[route.Priority] {
			return errors.New("relay failover routes require unique IDs and priorities")
		}
		ids[route.ID], priorities[route.Priority] = true, true
		switch route.Kind {
		case RouteRelay:
			if route.RelayEndpointID == "" || route.RelayEndpointID == policy.EndpointID {
				return errors.New("relay route requires a different approved relay endpoint")
			}
		case RouteDirect:
			directRoutes++
			if route.RelayEndpointID != "" || directRoutes > 1 {
				return errors.New("direct fallback must be explicit and unique")
			}
		default:
			return errors.New("relay failover route kind is invalid")
		}
	}
	return nil
}

func availableRouteIDs(observations []RouteAvailability, maximumAge time.Duration, now time.Time) map[string]bool {
	available := make(map[string]bool, len(observations))
	seen := make(map[string]bool, len(observations))
	for _, observation := range observations {
		if observation.RouteID == "" {
			continue
		}
		if seen[observation.RouteID] {
			delete(available, observation.RouteID)
			continue
		}
		seen[observation.RouteID] = true
		if !observation.Healthy || observation.ObservedAt.IsZero() || observation.ObservedAt.After(now.Add(5*time.Minute)) || observation.ObservedAt.Before(now.Add(-maximumAge)) {
			continue
		}
		available[observation.RouteID] = true
	}
	return available
}
