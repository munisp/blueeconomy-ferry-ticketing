package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// ticketArtifactClaims is the signed ticket-proof payload. The field order of
// this struct is the canonical signing serialization — never reorder fields.
// Raw passenger PII never appears here: only the salted digest, exactly as on
// the ticket record.
type ticketArtifactClaims struct {
	TicketID        string `json:"ticketId"`
	TripID          string `json:"tripId"`
	OperatorID      string `json:"operatorId"`
	State           string `json:"state"`
	FareNGNMinor    int64  `json:"fareNgnMinor"`
	SeatNumber      *int   `json:"seatNumber,omitempty"`
	PassengerDigest string `json:"passengerDigestSha256"`
	Version         int64  `json:"version"`
}

// ticketArtifact is the signed proof returned to mobile clients: the claims,
// the key identifier and the HMAC-SHA256 signature over the canonical claims
// JSON.
type ticketArtifact struct {
	Claims    ticketArtifactClaims `json:"claims"`
	KeyID     string               `json:"keyId"`
	Algorithm string               `json:"algorithm"`
	Signature string               `json:"signature"`
}

// proofAlgorithm is the ticket-proof signature scheme. The repository's only
// issuance key material is the manifest salt, so ticket proofs reuse it as an
// HMAC-SHA256 key; verification secrets are provisioned to offline verifiers
// out of band and are never served by this API.
const proofAlgorithm = "HMAC-SHA256"

// proofKeyID derives the public key identifier for the configured proof key
// without exposing the key material itself.
func (server *Server) proofKeyID() (string, bool) {
	if len(server.salt) < 16 {
		return "", false
	}
	sum := sha256.Sum256([]byte("ferry-ticket-proof-key-id\x00" + server.salt))
	return hex.EncodeToString(sum[:8]), true
}

// signArtifactClaims signs the canonical claims JSON fail-closed.
func (server *Server) signArtifactClaims(claims ticketArtifactClaims) (ticketArtifact, bool) {
	keyID, ok := server.proofKeyID()
	if !ok {
		return ticketArtifact{}, false
	}
	canonical, err := json.Marshal(claims)
	if err != nil {
		return ticketArtifact{}, false
	}
	mac := hmac.New(sha256.New, []byte(server.salt))
	mac.Write([]byte("ferry-ticket-proof\x00"))
	mac.Write(canonical)
	return ticketArtifact{
		Claims:    claims,
		KeyID:     keyID,
		Algorithm: proofAlgorithm,
		Signature: hex.EncodeToString(mac.Sum(nil)),
	}, true
}

func artifactClaimsOf(ticket ticketing.Ticket) ticketArtifactClaims {
	return ticketArtifactClaims{
		TicketID:        ticket.TicketID,
		TripID:          ticket.TripID,
		OperatorID:      ticket.OperatorID,
		State:           string(ticket.State),
		FareNGNMinor:    ticket.FareNGNMinor,
		SeatNumber:      ticket.SeatNumber,
		PassengerDigest: ticket.PassengerDigest,
		Version:         ticket.Version,
	}
}

// ticketArtifact handles GET /v1/tickets/{id}/artifact: the signed ticket
// proof payload for mobile wallets. Read scope matches the ticket read
// (owner, owning operator or oversight); an unconfigured proof key fails
// closed with 503.
func (server *Server) ticketArtifact(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	ticket, err := server.operator.GetTicket(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if !canReadTicket(resolved, ticket) {
		writeError(writer, http.StatusForbidden, "forbidden")
		return
	}
	artifact, ok := server.signArtifactClaims(artifactClaimsOf(ticket))
	if !ok {
		server.logger.Warn("ticket proof signing requested but proof key is not configured")
		writeError(writer, http.StatusServiceUnavailable, "ticket proof signing is not configured")
		return
	}
	writeJSON(writer, http.StatusOK, artifact)
}

// verificationKeys handles GET /v1/tickets/verification-keys: the public key
// descriptors offline verifiers use to check ticket artifacts. The key
// material itself is a shared secret provisioned out of band and is never
// served; when no proof key is configured the endpoint fails closed with 503.
func (server *Server) verificationKeys(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	keyID, ok := server.proofKeyID()
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "ticket verification keys are not configured")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"keys": []map[string]string{{
			"keyId":     keyID,
			"algorithm": proofAlgorithm,
			"use":       "ticket-proof",
			// HMAC verification requires the shared secret; it is distributed
			// to authorized offline verifiers out of band, never via this API.
			"distribution": "out-of-band",
		}},
	})
}

// verifyScanBody is one scan-confirmation request: the artifact claims and
// signature presented by the ticket holder.
type verifyScanBody struct {
	TicketID  string `json:"ticketId"`
	KeyID     string `json:"keyId"`
	Signature string `json:"signature"`
}

// verifyTicketScan handles POST /v1/tickets/verify: gate/inspector scan
// confirmation. The presented signature is recomputed from the authoritative
// ticket record and compared in constant time; any mismatch, stale version or
// wrong key answers valid=false — the path never trusts the presented claims
// over the database.
func (server *Server) verifyTicketScan(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	var body verifyScanBody
	if !decodeBody(writer, request, &body) {
		return
	}
	if strings.TrimSpace(body.TicketID) == "" || strings.TrimSpace(body.Signature) == "" {
		writeError(writer, http.StatusBadRequest, "ticketId and signature are required")
		return
	}
	keyID, ok := server.proofKeyID()
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "ticket proof verification is not configured")
		return
	}
	ticket, err := server.operator.GetTicket(request.Context(), body.TicketID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	artifact, ok := server.signArtifactClaims(artifactClaimsOf(ticket))
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "ticket proof verification is not configured")
		return
	}
	presented, err := hex.DecodeString(body.Signature)
	if err != nil {
		writeJSON(writer, http.StatusOK, map[string]any{"valid": false, "reason": "malformed signature"})
		return
	}
	expected, _ := hex.DecodeString(artifact.Signature)
	valid := body.KeyID == keyID && hmac.Equal(presented, expected)
	response := map[string]any{
		"valid":    valid,
		"ticketId": ticket.TicketID,
		"state":    string(ticket.State),
		"embarked": ticket.Embarked,
	}
	if !valid {
		response["reason"] = "signature does not match the authoritative ticket record"
	} else if ticket.State != ticketing.StateIssued {
		// A well-formed proof of a non-issued ticket is not boardable.
		response["valid"] = false
		response["reason"] = "ticket is not in ISSUED state"
	}
	writeJSON(writer, http.StatusOK, response)
}
