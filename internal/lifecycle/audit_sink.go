package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// AuditSink durably receives lifecycle audit events. Implementations must keep
// secret material out of their serialized representation.
type AuditSink interface {
	Append(ctx context.Context, event protocol.LifecycleEvent) error
	Close() error
}

// AuditLogger is the small logging boundary used by audit fan-out and store
// wiring. It deliberately matches log.Printf without depending on log.Logger.
type AuditLogger func(format string, args ...any)

var ErrAuditSinkClosed = errors.New("audit sink is closed")

// FileAuditSinkConfig configures a JSON-lines audit file. Writes are fsynced by
// default so a successful Append represents a durable append; callers may
// disable per-write fsync when the filesystem already provides the needed
// durability and use their own batching policy.
type FileAuditSinkConfig struct {
	Path      string
	FsyncEach bool
}

// FileAuditSink is an append-only, mutex-serialized JSON-lines writer. The
// file contains only redacted protocol LifecycleEvent objects, one per line.
type FileAuditSink struct {
	mu        sync.Mutex
	file      *os.File
	fsyncEach bool
	closed    bool
}

// NewFileAuditSink opens path for append, creating its parent directories and
// the file with owner-only permissions. Existing content is never truncated.
func NewFileAuditSink(path string) (*FileAuditSink, error) {
	return NewFileAuditSinkWithConfig(FileAuditSinkConfig{Path: path, FsyncEach: true})
}

// NewFileAuditSinkWithConfig constructs a file sink with explicit durability
// settings. A blank path is rejected rather than silently disabling auditing.
func NewFileAuditSinkWithConfig(config FileAuditSinkConfig) (*FileAuditSink, error) {
	path := strings.TrimSpace(config.Path)
	if path == "" {
		return nil, errors.New("audit file path is required")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, fmt.Errorf("create audit file directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("protect audit file: %w", err)
	}
	return &FileAuditSink{file: file, fsyncEach: config.FsyncEach}, nil
}

// Append adds one redacted event and a newline atomically with respect to
// other appends on this sink. Context cancellation is honored before the
// filesystem write.
func (s *FileAuditSink) Append(ctx context.Context, event protocol.LifecycleEvent) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	payload, err := json.Marshal(redactLifecycleEvent(event))
	if err != nil {
		return fmt.Errorf("encode lifecycle audit event: %w", err)
	}
	payload = append(payload, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.file == nil {
		return ErrAuditSinkClosed
	}
	if _, err := s.file.Write(payload); err != nil {
		return fmt.Errorf("append lifecycle audit event: %w", err)
	}
	if s.fsyncEach {
		if err := s.file.Sync(); err != nil {
			return fmt.Errorf("sync lifecycle audit event: %w", err)
		}
	}
	return nil
}

// Close flushes the file and is safe to call more than once.
func (s *FileAuditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.file == nil {
		return nil
	}
	var errs []error
	if err := s.file.Sync(); err != nil {
		errs = append(errs, fmt.Errorf("sync audit file: %w", err))
	}
	if err := s.file.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close audit file: %w", err))
	}
	s.file = nil
	return errors.Join(errs...)
}

// MultiAuditSink fans one event to every configured sink. A sink failure is
// isolated and logged; other sinks still receive the event and Append returns
// nil so an optional audit destination cannot break lifecycle operations.
type MultiAuditSink struct {
	mu     sync.Mutex
	sinks  []AuditSink
	logger AuditLogger
	closed bool
}

// NewMultiAuditSink constructs a fan-out sink. Nil sinks are ignored; at least
// one real sink is required so an accidental empty configuration is visible.
func NewMultiAuditSink(logger AuditLogger, sinks ...AuditSink) (*MultiAuditSink, error) {
	filtered := make([]AuditSink, 0, len(sinks))
	for _, sink := range sinks {
		if sink != nil {
			filtered = append(filtered, sink)
		}
	}
	if len(filtered) == 0 {
		return nil, errors.New("at least one audit sink is required")
	}
	return &MultiAuditSink{sinks: filtered, logger: logger}, nil
}

func (s *MultiAuditSink) Append(ctx context.Context, event protocol.LifecycleEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrAuditSinkClosed
	}
	for _, sink := range s.sinks {
		if err := sink.Append(ctx, event); err != nil && s.logger != nil {
			s.logger("append audit event %s to sink: %v", event.ID, err)
		}
	}
	return nil
}

func (s *MultiAuditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	for _, sink := range s.sinks {
		if err := sink.Close(); err != nil {
			if s.logger != nil {
				s.logger("close audit sink: %v", err)
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// redactLifecycleEvent mirrors the existing integration event safety policy:
// secret-bearing detail keys are omitted and bearer-like values are replaced.
// LifecycleEvent has no secret fields, so this copy is the serialization
// boundary that prevents a provider error or future detail from leaking one.
func redactLifecycleEvent(event protocol.LifecycleEvent) protocol.LifecycleEvent {
	safe := event
	safe.Summary = redactAuditText(event.Summary)
	safe.Details = redactAuditDetails(event.Details)
	return safe
}

// redactIntegrationEvent applies the same serialization boundary to the
// short-lived Redis receipt types. The integration manager rejects unsafe
// details before publication; this second boundary protects direct publisher
// callers and keeps MemoryEventPublisher's documented invariant true too.
func redactIntegrationEvent(event protocol.AzureIntegrationEvent) protocol.AzureIntegrationEvent {
	safe := event
	safe.Details = redactAuditDetails(event.Details)
	return safe
}

func redactAuditDetails(details map[string]string) map[string]string {
	if details == nil {
		return nil
	}
	safe := make(map[string]string, len(details))
	for key, value := range details {
		if sensitiveAuditKey(key) {
			continue
		}
		safe[key] = redactAuditText(value)
	}
	return safe
}

func sensitiveAuditKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(key))
	return strings.Contains(normalized, "secrettext") ||
		strings.Contains(normalized, "clientsecret") ||
		strings.Contains(normalized, "privatekey") ||
		strings.Contains(normalized, "awssecretaccesskey") ||
		strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "accesstoken") ||
		normalized == "token" || normalized == "secret"
}

func redactAuditText(value string) string {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"bearer ", "client_secret", "clientsecret", "secret_text", "secrettext",
		"private_key", "privatekey", "aws_secret_access_key", "awssecretaccesskey",
		"password", "access_token",
	} {
		if strings.Contains(lower, marker) {
			return "[REDACTED]"
		}
	}
	return value
}
