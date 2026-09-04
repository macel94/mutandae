package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func TestFileAuditSinkAppendsOrderedJSONLAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.jsonl")
	events := []protocol.LifecycleEvent{
		{ID: "evt-1", IdentityID: "one", Type: protocol.EventIdentityRegistered, Summary: "one"},
		{ID: "evt-2", IdentityID: "one", Type: protocol.EventRotationStarted, Summary: "two"},
		{ID: "evt-3", IdentityID: "one", Type: protocol.EventRotationCompleted, Summary: "three"},
	}
	sink, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("NewFileAuditSink: %v", err)
	}
	for _, event := range events[:2] {
		if err := sink.Append(context.Background(), event); err != nil {
			t.Fatalf("Append(%s): %v", event.ID, err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("audit file mode = %o, want 0600", got)
	}

	restarted, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("restart NewFileAuditSink: %v", err)
	}
	if err := restarted.Append(context.Background(), events[2]); err != nil {
		t.Fatalf("restart Append: %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatalf("restart Close: %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	defer file.Close()
	var got []protocol.LifecycleEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event protocol.LifecycleEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("invalid JSONL %q: %v", scanner.Text(), err)
		}
		got = append(got, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit file: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("event count = %d, want %d", len(got), len(events))
	}
	for i := range events {
		if got[i].ID != events[i].ID {
			t.Errorf("event[%d].ID = %q, want %q", i, got[i].ID, events[i].ID)
		}
	}
}

func TestFileAuditSinkConcurrentAppendProducesValidJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := NewFileAuditSinkWithConfig(FileAuditSinkConfig{Path: path, FsyncEach: false})
	if err != nil {
		t.Fatalf("NewFileAuditSink: %v", err)
	}
	const writers = 12
	const eventsPerWriter = 20
	var wg sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		writer := writer
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := 0; index < eventsPerWriter; index++ {
				event := protocol.LifecycleEvent{ID: fmt.Sprintf("evt-%d-%d", writer, index), Type: protocol.EventRenewalAlerted}
				if err := sink.Append(context.Background(), event); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	defer file.Close()
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event protocol.LifecycleEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("line %d invalid JSON: %v", count, err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit file: %v", err)
	}
	want := writers * eventsPerWriter
	if count != want {
		t.Fatalf("JSONL event count = %d, want %d", count, want)
	}
}

func TestFileAuditSinkRedactsSecretLookingDetails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("NewFileAuditSink: %v", err)
	}
	event := protocol.LifecycleEvent{
		ID: "evt-redacted", Type: protocol.EventCredentialDelivered,
		Summary: "credential delivery completed",
		Details: map[string]string{
			"client_secret":         "customer-secret",
			"secretText":            "customer-secret",
			"privateKey":            "private-key-material",
			"AWS_SECRET_ACCESS_KEY": "aws-secret-material",
			"token":                 "bearer-token",
			"key_id":                "safe-key",
		},
	}
	if err := sink.Append(context.Background(), event); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	output := string(payload)
	for _, forbidden := range []string{"client_secret", "secretText", "privateKey", "AWS_SECRET_ACCESS_KEY", "token", "customer-secret", "private-key-material", "aws-secret-material"} {
		if strings.Contains(output, forbidden) {
			t.Errorf("audit output contains forbidden %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "safe-key") {
		t.Error("safe audit detail was removed")
	}
}

type recordingAuditSink struct {
	mu     sync.Mutex
	events []protocol.LifecycleEvent
	err    error
	closed bool
}

func (s *recordingAuditSink) Append(_ context.Context, event protocol.LifecycleEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	return nil
}

func (s *recordingAuditSink) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func TestMultiAuditSinkIsolatesAppendErrors(t *testing.T) {
	bad := &recordingAuditSink{err: errors.New("disk full")}
	good := &recordingAuditSink{}
	var logged string
	multi, err := NewMultiAuditSink(func(format string, args ...any) { logged += fmt.Sprintf(format, args...) }, bad, good)
	if err != nil {
		t.Fatalf("NewMultiAuditSink: %v", err)
	}
	event := protocol.LifecycleEvent{ID: "evt-multi", Type: protocol.EventIdentityRegistered}
	if err := multi.Append(context.Background(), event); err != nil {
		t.Fatalf("MultiAuditSink.Append: %v", err)
	}
	if len(good.events) != 1 || good.events[0].ID != event.ID {
		t.Fatalf("good sink events = %+v, want one event", good.events)
	}
	if !strings.Contains(logged, "disk full") {
		t.Fatalf("logger output = %q, want sink error", logged)
	}
}

func TestMemoryEventPublisherRedactsSecretLookingDetails(t *testing.T) {
	publisher := &MemoryEventPublisher{}
	event := protocol.AzureIntegrationEvent{
		ID: "evt-memory-redacted", Type: string(protocol.EventSecretCreated), CorrelationID: "op-memory-redacted",
		Details: map[string]string{
			"clientSecret":          "customer-secret",
			"secretText":            "customer-secret",
			"privateKey":            "private-key-material",
			"AWS_SECRET_ACCESS_KEY": "aws-secret-material",
			"token":                 "bearer-token",
			"key_id":                "safe-key",
		},
	}
	if err := publisher.Publish(context.Background(), event); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(publisher.Events) != 1 {
		t.Fatalf("published events = %d, want 1", len(publisher.Events))
	}
	encoded, err := json.Marshal(publisher.Events[0])
	if err != nil {
		t.Fatalf("marshal published event: %v", err)
	}
	output := string(encoded)
	for _, forbidden := range []string{"clientSecret", "secretText", "privateKey", "AWS_SECRET_ACCESS_KEY", "token", "customer-secret", "private-key-material", "aws-secret-material"} {
		if strings.Contains(output, forbidden) {
			t.Errorf("memory publisher output contains forbidden %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "safe-key") {
		t.Error("safe event detail was removed")
	}
}

func TestStoreWiresLifecycleEventsToAuditSink(t *testing.T) {
	sink := &recordingAuditSink{}
	store, err := NewStore(context.Background(), now(), &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}, WithAuditSink(sink))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if _, err := store.Rotate(context.Background(), protocol.RotateRequest{ID: "payments-api"}, now()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	events, ok := store.Events("payments-api")
	if !ok || len(events) != len(sink.events) {
		t.Fatalf("stored events = %d, sink events = %d", len(events), len(sink.events))
	}
	for index := range events {
		want := events[len(events)-1-index]
		if want.ID != sink.events[index].ID {
			t.Errorf("sink event[%d] = %q, want %q", index, sink.events[index].ID, want.ID)
		}
	}
}
