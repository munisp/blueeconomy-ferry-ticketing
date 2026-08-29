package telemetry

import (
	"context"
	"fmt"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPGXPool opens a pgx pool with the otelpgx query tracer attached, so
// every query, batch, prepared statement, copy and acquire emits a span under
// the active trace. When telemetry is disabled the spans are no-ops and the
// pool behaves exactly as before (fail-open telemetry, fail-closed database).
func NewPGXPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	config.ConnConfig.Tracer = otelpgx.NewTracer()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return pool, nil
}
