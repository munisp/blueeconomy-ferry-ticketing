package metocean

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

// kafka-go wiring for the bridge. Transport security is env-only and
// fail-closed: SASL credentials arrive through the environment, TLS material
// through mounted files, and the configuration loader refuses plaintext-only
// deployments.

// kafkaMessageSource adapts a kafka-go consumer-group reader to
// MessageSource.
type kafkaMessageSource struct {
	reader *kafka.Reader
}

// kafkaSink adapts a kafka-go writer to Sink.
type kafkaSink struct {
	writer *kafka.Writer
}

// NewKafkaMessageSource builds the consumer-group reader for the advisory
// topic with the configured SASL/TLS transport.
func NewKafkaMessageSource(config Config) (MessageSource, error) {
	dialer, err := kafkaDialer(config)
	if err != nil {
		return nil, err
	}
	return &kafkaMessageSource{reader: kafka.NewReader(kafka.ReaderConfig{
		Brokers:  config.KafkaBrokers,
		Topic:    config.KafkaTopic,
		GroupID:  config.KafkaGroupID,
		Dialer:   dialer,
		MinBytes: 1,
		MaxBytes: 10 << 20,
		// Offsets are committed explicitly after terminal handling (dispatch,
		// rejection+dead-letter), never before.
		CommitInterval: 0,
	})}, nil
}

// NewKafkaSink builds the dead-letter writer with the configured SASL/TLS
// transport and all-broker acknowledgments.
func NewKafkaSink(config Config) (Sink, error) {
	dialer, err := kafkaDialer(config)
	if err != nil {
		return nil, err
	}
	return &kafkaSink{writer: &kafka.Writer{
		Addr:         kafka.TCP(config.KafkaBrokers...),
		Topic:        config.KafkaDLQTopic,
		RequiredAcks: kafka.RequireAll,
		Transport:    &kafka.Transport{SASL: dialer.SASLMechanism, TLS: dialer.TLS},
	}}, nil
}

// Fetch implements MessageSource.
func (source *kafkaMessageSource) Fetch(ctx context.Context) (Message, error) {
	record, err := source.reader.FetchMessage(ctx)
	if err != nil {
		return Message{}, err
	}
	headers := make([]Header, 0, len(record.Headers))
	for _, header := range record.Headers {
		headers = append(headers, Header{Key: header.Key, Value: header.Value})
	}
	return Message{
		Key:       record.Key,
		Value:     record.Value,
		Headers:   headers,
		Topic:     record.Topic,
		Partition: record.Partition,
		Offset:    record.Offset,
	}, nil
}

// Commit implements MessageSource.
func (source *kafkaMessageSource) Commit(ctx context.Context, message Message) error {
	return source.reader.CommitMessages(ctx, kafka.Message{
		Topic:     message.Topic,
		Partition: message.Partition,
		Offset:    message.Offset,
	})
}

// Close implements MessageSource.
func (source *kafkaMessageSource) Close() error { return source.reader.Close() }

// Publish implements Sink.
func (sink *kafkaSink) Publish(ctx context.Context, key, value []byte, headers []Header) error {
	if len(value) == 0 {
		return errors.New("dead-letter payload is required")
	}
	record := kafka.Message{Key: key, Value: value}
	for _, header := range headers {
		record.Headers = append(record.Headers, kafka.Header{Key: header.Key, Value: header.Value})
	}
	if err := sink.writer.WriteMessages(ctx, record); err != nil {
		return fmt.Errorf("write dead-letter record: %w", err)
	}
	return nil
}

// Close implements Sink.
func (sink *kafkaSink) Close() error { return sink.writer.Close() }

// kafkaDialer assembles the SASL/TLS dialer from the validated
// configuration. TLS is system-roots-plus-configured-CA; there is no
// insecure-skip-verify escape hatch.
func kafkaDialer(config Config) (*kafka.Dialer, error) {
	dialer := &kafka.Dialer{Timeout: 10 * time.Second, DualStack: true}
	var tlsConfig *tls.Config
	if config.TLSCAFile != "" || config.TLSCertFile != "" {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if config.TLSCAFile != "" {
			pem, err := os.ReadFile(config.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("read Kafka TLS CA file: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("Kafka TLS CA file %q carries no PEM certificates", config.TLSCAFile)
			}
			tlsConfig.RootCAs = pool
		}
		if config.TLSCertFile != "" {
			certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load Kafka TLS client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{certificate}
		}
	}
	dialer.TLS = tlsConfig

	var mechanism sasl.Mechanism
	switch config.SASLMechanism {
	case "":
	case SASLPlain:
		mechanism = plain.Mechanism{Username: config.SASLUsername, Password: config.SASLPassword}
	case SASLScramSHA256, SASLScramSHA512:
		algorithm := scram.SHA256
		if config.SASLMechanism == SASLScramSHA512 {
			algorithm = scram.SHA512
		}
		created, err := scram.Mechanism(algorithm, config.SASLUsername, config.SASLPassword)
		if err != nil {
			return nil, fmt.Errorf("configure Kafka SASL %s: %w", config.SASLMechanism, err)
		}
		mechanism = created
	default:
		return nil, fmt.Errorf("Kafka SASL mechanism %q is not supported", config.SASLMechanism)
	}
	dialer.SASLMechanism = mechanism
	return dialer, nil
}
