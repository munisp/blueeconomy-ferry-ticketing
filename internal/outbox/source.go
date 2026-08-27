package outbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresSource implements EventSource against the ferry_outbox table.
type PostgresSource struct {
	pool *pgxpool.Pool
}

// NewPostgresSource fails closed on a nil pool.
func NewPostgresSource(pool *pgxpool.Pool) (*PostgresSource, error) {
	if pool == nil {
		return nil, errors.New("postgres pool is required")
	}
	return &PostgresSource{pool: pool}, nil
}

// Unpublished implements EventSource.
func (source *PostgresSource) Unpublished(ctx context.Context, limit int) ([]Event, error) {
	if limit <= 0 {
		return nil, errors.New("limit must be positive")
	}
	rows, err := source.pool.Query(ctx,
		`SELECT event_id, topic, subject_id, event_type, payload, correlation_id, created_at
		 FROM ferry_outbox WHERE published_at IS NULL ORDER BY created_at LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("query unpublished outbox: %w", err)
	}
	defer rows.Close()
	events := make([]Event, 0)
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.EventID, &event.Topic, &event.SubjectID, &event.EventType,
			&event.Payload, &event.CorrelationID, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan outbox event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// MarkPublished implements EventSource; it fails when the event was already
// marked or does not exist.
func (source *PostgresSource) MarkPublished(ctx context.Context, event Event) error {
	result, err := source.pool.Exec(ctx,
		`UPDATE ferry_outbox SET published_at = now() WHERE event_id = $1 AND published_at IS NULL`,
		event.EventID)
	if err != nil {
		return fmt.Errorf("mark outbox event published: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("outbox event %s is missing or already published", event.EventID)
	}
	return nil
}
