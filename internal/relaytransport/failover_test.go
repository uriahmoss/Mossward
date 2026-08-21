package relaytransport

import (
	"errors"
	"testing"
	"time"
)

func TestFailoverUsesOnlyHealthyApprovedRoutesAfterThreshold(t *testing.T) {
	now := time.Now().UTC()
	controller := testFailoverController(t)
	availability := []RouteAvailability{{RouteID: "primary", Healthy: true, ObservedAt: now},
		{RouteID: "secondary", Healthy: true, ObservedAt: now}, {RouteID: "unapproved", Healthy: true, ObservedAt: now}}
	decision, err := controller.Select(availability, now)
	if err != nil || decision.Route.ID != "primary" || decision.Reason != "approved_initial_route" {
		t.Fatalf("initial decision = %#v, error = %v", decision, err)
	}
	if err := controller.RecordDelivery("primary", false); err != nil {
		t.Fatal(err)
	}
	decision, err = controller.Select(availability, now.Add(time.Second))
	if err != nil || decision.Route.ID != "primary" {
		t.Fatalf("route failed over before threshold: %#v %v", decision, err)
	}
	if err := controller.RecordDelivery("primary", false); err != nil {
		t.Fatal(err)
	}
	decision, err = controller.Select(availability, now.Add(2*time.Second))
	if err != nil || decision.Route.ID != "secondary" || decision.PreviousRouteID != "primary" || decision.ConsecutiveFailures != 2 {
		t.Fatalf("failover decision = %#v, error = %v", decision, err)
	}
}

func TestFailoverRejectsUnapprovedStaleAndAutomaticFailback(t *testing.T) {
	now := time.Now().UTC()
	controller := testFailoverController(t)
	availability := []RouteAvailability{{RouteID: "unapproved", Healthy: true, ObservedAt: now},
		{RouteID: "primary", Healthy: true, ObservedAt: now.Add(-2 * time.Minute)}}
	if _, err := controller.Select(availability, now); !errors.Is(err, ErrNoApprovedRoute) {
		t.Fatalf("unsafe route selection result = %v", err)
	}
	availability = []RouteAvailability{{RouteID: "secondary", Healthy: true, ObservedAt: now}}
	decision, err := controller.Select(availability, now)
	if err != nil || decision.Route.ID != "secondary" {
		t.Fatalf("secondary selection = %#v, error = %v", decision, err)
	}
	availability = append(availability, RouteAvailability{RouteID: "primary", Healthy: true, ObservedAt: now})
	decision, err = controller.Select(availability, now)
	if err != nil || decision.Route.ID != "secondary" {
		t.Fatalf("unexpected automatic failback = %#v, error = %v", decision, err)
	}
	decision, err = controller.SelectApprovedRoute("primary", availability, now)
	if err != nil || decision.Route.ID != "primary" || decision.Reason != "server_selected_approved_route" {
		t.Fatalf("explicit failback = %#v, error = %v", decision, err)
	}
}

func TestFailoverPolicyRequiresExplicitSafeRoutes(t *testing.T) {
	base := FailoverPolicy{EndpointID: "endpoint", FailureThreshold: 2, ObservationMaxAge: time.Minute}
	unsafe := []ApprovedRoute{{ID: "self", Kind: RouteRelay, RelayEndpointID: "endpoint", Priority: 1}}
	base.Routes = unsafe
	if _, err := NewFailoverController(base); err == nil {
		t.Fatal("self-relay route was accepted")
	}
	base.Routes = []ApprovedRoute{{ID: "direct-1", Kind: RouteDirect, Priority: 1}, {ID: "direct-2", Kind: RouteDirect, Priority: 2}}
	if _, err := NewFailoverController(base); err == nil {
		t.Fatal("multiple direct fallbacks were accepted")
	}
}

func TestFailoverRejectsAmbiguousRouteHealth(t *testing.T) {
	now := time.Now().UTC()
	controller := testFailoverController(t)
	availability := []RouteAvailability{{RouteID: "primary", Healthy: true, ObservedAt: now},
		{RouteID: "primary", Healthy: false, ObservedAt: now}}
	if _, err := controller.Select(availability, now); !errors.Is(err, ErrNoApprovedRoute) {
		t.Fatalf("ambiguous route health was accepted: %v", err)
	}
}

func testFailoverController(t *testing.T) *FailoverController {
	t.Helper()
	controller, err := NewFailoverController(FailoverPolicy{EndpointID: "endpoint", FailureThreshold: 2, ObservationMaxAge: time.Minute,
		Routes: []ApprovedRoute{{ID: "secondary", Kind: RouteRelay, RelayEndpointID: "relay-2", Priority: 2},
			{ID: "primary", Kind: RouteRelay, RelayEndpointID: "relay-1", Priority: 1}, {ID: "direct", Kind: RouteDirect, Priority: 3}}})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}
