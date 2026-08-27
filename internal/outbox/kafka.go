package outbox

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/segmentio/kafka-go"
)

// KafkaProducer publishes envelopes to one Kafka topic with all-broker acks.
type KafkaProducer struct {
	writer *kafka.Writer
}

// NewKafkaProducer fails closed on missing brokers or topic. The producer
// requires full acknowledgment so a Kafka outage surfaces as an error rather
// than silent loss.
func NewKafkaProducer(brokers, topic string) (*KafkaProducer, error) {
	addresses := make([]string, 0)
	for _, broker := range strings.Split(brokers, ",") {
		broker = strings.TrimSpace(broker)
		if broker == "" {
			return nil, errors.New("Kafka broker list contains an empty address")
		}
		addresses = append(addresses, broker)
	}
	if len(addresses) == 0 {
		return nil, errors.New("at least one Kafka broker is required")
	}
	if _, ok := topics[topic]; !ok {
		return nil, fmt.Errorf("Kafka topic %q is not approved", topic)
	}
	return &KafkaProducer{writer: &kafka.Writer{
		Addr:         kafka.TCP(addresses...),
		Topic:        topic,
		RequiredAcks: kafka.RequireAll,
	}}, nil
}

// Publish writes one keyed message. The key is the outbox event ID, making
// at-least-once replays idempotent for downstream consumers.
func (producer *KafkaProducer) Publish(ctx context.Context, key, value []byte) error {
	if len(key) == 0 || len(value) == 0 {
		return errors.New("Kafka key and value are required")
	}
	if err := producer.writer.WriteMessages(ctx, kafka.Message{Key: key, Value: value}); err != nil {
		return fmt.Errorf("write Kafka message: %w", err)
	}
	return nil
}

// Close releases the writer.
func (producer *KafkaProducer) Close() error { return producer.writer.Close() }
