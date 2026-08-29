package fare

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/passproof"
)

// ValidationService mints and validates signed pass artifacts (BFP1). The
// ADMIT/DENY decision never reveals PII: reasons are stable codes and the
// response carries only product scope and validity.
type ValidationService struct {
	store  *PostgresStore
	signer *passproof.Signer
	now    func() time.Time
}

// NewValidationService fails closed on any missing dependency.
func NewValidationService(store *PostgresStore, signer *passproof.Signer) (*ValidationService, error) {
	if store == nil {
		return nil, errors.New("fare store is required")
	}
	if signer == nil {
		return nil, errors.New("pass validation signer is required (fail-closed)")
	}
	return &ValidationService{store: store, signer: signer,
		now: func() time.Time { return time.Now().UTC() }}, nil
}

// ProvisionKeyDirectory upserts the configured signing epoch as CURRENT at
// boot (rotating validation keys; devices cache the directory).
func (service *ValidationService) ProvisionKeyDirectory(ctx context.Context) error {
	return service.store.EnsureValidationKeyDirectory(ctx, int(service.signer.Epoch()),
		passproof.KeyIDString(service.signer.Public()), hex.EncodeToString(service.signer.Public()))
}

// MintArtifact signs the BFP1 artifact for one pass. Only ACTIVE passes mint.
func (service *ValidationService) MintArtifact(ctx context.Context, passID string) (string, error) {
	pass, err := service.store.GetPass(ctx, passID)
	if err != nil {
		return "", err
	}
	if pass.Status != PassStatusActive {
		return "", fmt.Errorf("%w: %s passes cannot mint a validation artifact", ErrInvalidTransition, pass.Status)
	}
	product, err := service.store.GetPassProduct(ctx, pass.ProductID)
	if err != nil {
		return "", fmt.Errorf("load pass product: %w", err)
	}
	scopeCode, err := passproof.ScopeCode(product.ScopeType)
	if err != nil {
		return "", err
	}
	return service.signer.Sign(passproof.Payload{
		PassID:       pass.PassID,
		ProductID:    product.ProductID,
		ScopeType:    scopeCode,
		ScopeRef:     product.ScopeRef,
		ValidFrom:    pass.ValidFrom,
		ValidTo:      pass.ValidTo,
		HolderDigest: pass.OwnerDigest,
	}, service.now())
}

// verifier builds the offline-equivalent verifier from the cached key
// directory (CURRENT + PREVIOUS epochs). This is byte-identical to what a
// conductor device does with its synced cache.
func (service *ValidationService) verifier(ctx context.Context) (*passproof.Verifier, error) {
	rows, err := service.store.ListValidationKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]passproof.TrustedKey, 0, len(rows))
	for _, row := range rows {
		public, err := hex.DecodeString(row.PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("validation key epoch %d has malformed public key", row.Epoch)
		}
		keys = append(keys, passproof.TrustedKey{KeyID: row.Kid, Public: public, Epoch: uint32(row.Epoch)})
	}
	return passproof.NewVerifier(keys)
}

// Validate decides ADMIT/DENY for one presented pass artifact. Cryptographic
// failures (wrong/unknown epoch, bad signature, malformed) hard-fail; policy
// failures map to the advisory's reason set (not_valid_yet, expired,
// revoked, suspended, out_of_scope). No PII is ever returned.
func (service *ValidationService) Validate(ctx context.Context, token, routeReference string) ValidationDecision {
	verifier, err := service.verifier(ctx)
	if err != nil {
		return ValidationDecision{Admit: false, Reason: "key_directory_unavailable"}
	}
	payload, err := verifier.Verify(strings.TrimSpace(token))
	if err != nil {
		return ValidationDecision{Admit: false, Reason: passproof.FailureReason(err), PassID: payload.PassID, Epoch: payload.KeyEpoch}
	}
	decision := ValidationDecision{
		PassID: payload.PassID,
		Scope:  passproof.ScopeName(payload.ScopeType),
		ScopeRef: payload.ScopeRef,
		ValidTo:  payload.ValidTo.Format(time.RFC3339),
		Epoch:    payload.KeyEpoch,
	}
	now := service.now()
	if now.Before(payload.ValidFrom) {
		decision.Reason = "not_valid_yet"
		return decision
	}
	if !now.Before(payload.ValidTo) {
		decision.Reason = "expired"
		return decision
	}
	// Fail closed on the authoritative record: a cryptographically valid
	// artifact whose pass is unknown, suspended or revoked denies.
	pass, err := service.store.GetPass(ctx, payload.PassID)
	if err != nil {
		decision.Reason = "unknown_pass"
		return decision
	}
	switch pass.Status {
	case PassStatusActive:
	case PassStatusSuspended:
		decision.Reason = "suspended"
		return decision
	case PassStatusRevoked:
		decision.Reason = "revoked"
		return decision
	default:
		decision.Reason = "expired"
		return decision
	}
	if routeReference != "" && payload.ScopeType == passproof.ScopeRoute && payload.ScopeRef != routeReference {
		decision.Reason = "out_of_scope"
		return decision
	}
	decision.Admit = true
	return decision
}

// ValidationKeys returns the distributable key directory for device sync.
func (service *ValidationService) ValidationKeys(ctx context.Context) ([]ValidationKeyRow, error) {
	return service.store.ListValidationKeys(ctx)
}

// BlocklistPage is one signed, paginated blocklist delta for device sync.
type BlocklistPage struct {
	Epoch       uint32   `json:"epoch"`
	Since       string   `json:"since"`
	NextCursor  string   `json:"nextCursor"`
	PassIDs     []string `json:"passIds"`
	Signature   string   `json:"signature"`
	GeneratedAt string   `json:"generatedAt"`
}

// BlocklistDelta returns up to limit revoked pass ids strictly after the
// cursor ("<unix>:<pass_id>", empty = from the beginning), signed with the
// current validation key so devices verify the page offline.
func (service *ValidationService) BlocklistDelta(ctx context.Context, cursor string, limit int) (BlocklistPage, error) {
	if limit <= 0 || limit > 1000 {
		return BlocklistPage{}, errors.New("blocklist page limit must be within 1..1000")
	}
	since := time.Unix(0, 0).UTC()
	sincePassID := ""
	if cursor != "" {
		parts := strings.SplitN(cursor, ":", 2)
		if len(parts) != 2 {
			return BlocklistPage{}, errors.New("blocklist cursor is malformed")
		}
		unix, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return BlocklistPage{}, errors.New("blocklist cursor is malformed")
		}
		since = time.Unix(unix, 0).UTC()
		sincePassID = parts[1]
	}
	entries, err := service.store.ListRevocationsSince(ctx, since, sincePassID, limit)
	if err != nil {
		return BlocklistPage{}, err
	}
	passIDs := make([]string, 0, len(entries))
	nextCursor := cursor
	for _, entry := range entries {
		passIDs = append(passIDs, entry.PassID)
		nextCursor = fmt.Sprintf("%d:%s", entry.RevokedAt.Unix(), entry.PassID)
	}
	signature, err := service.signer.SignBlocklist(since.Unix(), passIDs)
	if err != nil {
		return BlocklistPage{}, err
	}
	return BlocklistPage{
		Epoch:       service.signer.Epoch(),
		Since:       cursor,
		NextCursor:  nextCursor,
		PassIDs:     passIDs,
		Signature:   signature,
		GeneratedAt: service.now().Format(time.RFC3339),
	}, nil
}
