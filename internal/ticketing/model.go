// Package ticketing implements the per-passenger ferry ticket lifecycle:
// RESERVED -> PAID -> ISSUED -> (REFUNDED | EXPIRED | VOID), capacity
// enforcement, idempotent purchase and the agent cash-in path. Raw passenger
// PII never crosses this boundary: passengers are salted digests.
package ticketing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// State is one ticket lifecycle state.
type State string

const (
	StateReserved State = "RESERVED"
	StatePaid     State = "PAID"
	StateIssued   State = "ISSUED"
	StateRefunded State = "REFUNDED"
	StateExpired  State = "EXPIRED"
	StateVoid     State = "VOID"
)

// Channel identifies how the fare was collected.
type Channel string

const (
	// ChannelDirect is an online/self-service payment.
	ChannelDirect Channel = "DIRECT"
	// ChannelAgentCashIn is cash collected by an accredited agent; it is
	// recorded as a cash-in ledger event against the agent float account.
	ChannelAgentCashIn Channel = "AGENT_CASH_IN"
)

var (
	// ErrInvalidTransition rejects any move outside the approved state graph.
	ErrInvalidTransition = errors.New("ticket state transition is not permitted")
	// ErrNotFound reports a missing record.
	ErrNotFound = errors.New("record not found")
	// ErrCapacityExceeded is the fail-closed overbooking rejection.
	ErrCapacityExceeded = errors.New("trip capacity is fully reserved")
	// ErrIdempotencyConflict reports a key replay against a different ticket.
	ErrIdempotencyConflict = errors.New("idempotency key is bound to a different ticket")
)

// transitions is the complete, approved state graph. Anything not listed
// fails closed.
var transitions = map[State][]State{
	StateReserved: {StatePaid, StateExpired, StateVoid},
	StatePaid:     {StateIssued, StateRefunded, StateVoid},
	StateIssued:   {StateRefunded, StateExpired, StateVoid},
}

// Terminal reports whether the state ends the lifecycle.
func (state State) Terminal() bool {
	switch state {
	case StateRefunded, StateExpired, StateVoid:
		return true
	}
	return false
}

// ValidTransition reports whether from -> to is approved.
func ValidTransition(from, to State) bool {
	for _, candidate := range transitions[from] {
		if candidate == to {
			return true
		}
	}
	return false
}

// Ticket is one per-passenger booking.
type Ticket struct {
	TicketID           string
	TripID             string
	OperatorID         string
	PassengerDigest    string
	FareNGNMinor       int64
	Channel            Channel
	State              State
	Version            int64
	SeatNumber         *int
	AgentID            string
	LedgerReserveID    string
	LedgerPostID       string
	PurchaserPrincipal string
	CorrelationID      string
	Embarked           bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Trip is a scheduled vessel departure with DB-enforced capacity.
type Trip struct {
	TripID             string
	VesselID           string
	OperatorID         string
	RouteReference     string
	TerminalReference  string
	ScheduledDeparture time.Time
	FareNGNMinor       int64
	Capacity           int
	SeatsReserved      int
	Status             string
}

// HasCapacity reports whether one more seat can be reserved.
func (trip Trip) HasCapacity() bool { return trip.SeatsReserved < trip.Capacity }

// Vessel is one operator-registered vessel.
type Vessel struct {
	VesselID   string
	OperatorID string
	Name       string
	IMONumber  string
	Capacity   int
	Active     bool
}

// PurchaseRequest carries one ticket purchase. PassengerRef is the opaque,
// tokenized passenger reference held inside the identity boundary; it is
// digested before persistence.
type PurchaseRequest struct {
	TripID         string
	PassengerRef   string
	Channel        Channel
	AgentID        string
	IdempotencyKey string
	CorrelationID  string
	Principal      string
	PrincipalRole  string
}

// Validate fails closed on any malformed purchase request.
func (request PurchaseRequest) Validate() error {
	if strings.TrimSpace(request.TripID) == "" {
		return errors.New("trip_id is required")
	}
	if strings.TrimSpace(request.PassengerRef) == "" || len(request.PassengerRef) > 256 {
		return errors.New("passenger reference is required")
	}
	switch request.Channel {
	case ChannelDirect:
	case ChannelAgentCashIn:
		if strings.TrimSpace(request.AgentID) == "" {
			return errors.New("agent_id is required for agent cash-in purchases")
		}
	default:
		return fmt.Errorf("channel %q is not supported", request.Channel)
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" || len(request.IdempotencyKey) > 128 {
		return errors.New("idempotency key is required")
	}
	if strings.TrimSpace(request.CorrelationID) == "" {
		return errors.New("correlation id is required")
	}
	if strings.TrimSpace(request.Principal) == "" {
		return errors.New("purchaser principal is required")
	}
	return nil
}

// PassengerDigest derives the salted, non-reversible passenger digest used on
// tickets, manifests and events. The salt is operator configuration; the
// digest is HMAC-SHA256 so length-extension and unsalted rainbow lookups do
// not apply.
func PassengerDigest(salt, passengerRef string) (string, error) {
	if salt == "" {
		return "", errors.New("manifest salt is required (fail-closed)")
	}
	if strings.TrimSpace(passengerRef) == "" {
		return "", errors.New("passenger reference is required")
	}
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(passengerRef))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Dashboard is the operator aggregate view.
type Dashboard struct {
	OperatorID       string         `json:"operatorId"`
	TicketsSold      int64          `json:"ticketsSold"`
	RevenueNGNMinor  int64          `json:"revenueNgnMinor"`
	PerCorridorStats []CorridorStat `json:"perCorridorStats"`
}

// CorridorStat aggregates one route corridor.
type CorridorStat struct {
	RouteReference  string `json:"routeReference"`
	TicketsSold     int64  `json:"ticketsSold"`
	RevenueNGNMinor int64  `json:"revenueNgnMinor"`
	TripsScheduled  int64  `json:"tripsScheduled"`
}
