package lifecycle

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func TestDeleteRequiresExplicitConfirmation(t *testing.T) {
	adapter := &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}
	store := testStore(t, adapter)

	if _, err := store.Delete(context.Background(), protocol.DeleteRequest{ID: "payments-api"}, now()); !errors.Is(err, ErrConfirmationNeeded) {
		t.Fatalf("without confirm error = %v, want ErrConfirmationNeeded", err)
	}
	if _, ok := store.Get("payments-api"); !ok {
		t.Fatal("record was purged without confirmation")
	}
}

func TestDeleteUnknownIdentityIsNotFound(t *testing.T) {
	store := testStore(t, &fakeAdapter{})
	if _, err := store.Delete(context.Background(), protocol.DeleteRequest{ID: "ghost", Confirm: true}, now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestDeleteRejectsIdentitiesThatAreNotRetired(t *testing.T) {
	adapter := &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}
	store := testStore(t, adapter)

	if _, err := store.Delete(context.Background(), protocol.DeleteRequest{ID: "payments-api", Confirm: true, Reason: "cleanup"}, now()); !errors.Is(err, ErrNotRetired) {
		t.Fatalf("error = %v, want ErrNotRetired", err)
	}
	if _, ok := store.Get("payments-api"); !ok {
		t.Fatal("an active identity was purged by delete")
	}
	if events, _ := store.Events("payments-api"); len(events) == 0 {
		t.Fatal("the rejected delete removed the audit trail")
	}
}

func TestDeletePurgesRetiredIdentityAndReturnsFinalEvidence(t *testing.T) {
	adapter := &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}
	store := testStore(t, adapter)
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: "payments-api", Confirm: true, Reason: "eol"}, now()); err != nil {
		t.Fatalf("Retire() error = %v", err)
	}

	resp, err := store.Delete(context.Background(), protocol.DeleteRequest{ID: "payments-api", Confirm: true, Reason: "decommission completely"}, now())
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if !resp.Deleted || resp.Identity.State != protocol.StateRetired || resp.Identity.ID != "payments-api" {
		t.Fatalf("response = (deleted=%v state=%s id=%s), want the final retired identity", resp.Deleted, resp.Identity.State, resp.Identity.ID)
	}
	if _, ok := store.Get("payments-api"); ok {
		t.Fatal("the record survived the delete")
	}
	if _, ok := store.Events("payments-api"); ok {
		t.Fatal("the audit trail survived the delete")
	}
	if _, ok := store.Runs("payments-api"); ok {
		t.Fatal("the rotation runs survived the delete")
	}
	if len(resp.Events) == 0 {
		t.Fatal("the delete response must carry the final audit snapshot")
	}
	deleted := resp.Events[len(resp.Events)-1]
	if deleted.Type != protocol.EventIdentityDeleted || deleted.Outcome != protocol.OutcomeSuccess {
		t.Fatalf("terminal event = (%s, %s), want (identity.deleted, success)", deleted.Type, deleted.Outcome)
	}
	if deleted.Details["reason"] != "decommission completely" {
		t.Fatalf("terminal event reason = %q", deleted.Details["reason"])
	}
	// The retirement event must still be in the snapshot the caller keeps.
	var sawRetired bool
	for _, event := range resp.Events {
		if event.Type == protocol.EventIdentityRetired {
			sawRetired = true
		}
	}
	if !sawRetired {
		t.Error("the final audit snapshot lost the retirement event")
	}
}

func TestDeleteReRevokesVaultCopiesAndAuditsFailureNonFatally(t *testing.T) {
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{
		discoveries: []protocol.MachineIdentity{discovered("payments-api")},
	}}}
	store := testStore(t, adapter)
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: "payments-api", Confirm: true}, now()); err != nil {
		t.Fatalf("Retire() error = %v", err)
	}
	revokesAfterRetire := len(adapter.revoked)

	// A failed re-revocation must not block the delete: the failure lands in
	// the final audit snapshot as an attention event.
	adapter.mu.Lock()
	adapter.failRevoke = errors.New("vault offline")
	adapter.mu.Unlock()
	resp, err := store.Delete(context.Background(), protocol.DeleteRequest{ID: "payments-api", Confirm: true, Reason: "purge"}, now())
	if err != nil {
		t.Fatalf("Delete() with failing vault error = %v", err)
	}
	if revokesAfterRetire != 1 {
		t.Fatalf("retire revocations = %d, want 1", revokesAfterRetire)
	}
	var sawAttention bool
	for _, event := range resp.Events {
		if event.Type == protocol.EventCredentialRevoked && event.Outcome == protocol.OutcomeAttention {
			sawAttention = true
		}
	}
	if !sawAttention {
		t.Error("the failed delete-time revocation was not audited in the final snapshot")
	}
	if _, ok := store.Get("payments-api"); ok {
		t.Error("the record survived a delete whose vault re-revocation failed")
	}
}

func TestDeleteReRevokesWhenRetirementRevocationFailed(t *testing.T) {
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{
		discoveries: []protocol.MachineIdentity{discovered("payments-api")},
	}}}
	store := testStore(t, adapter)
	// Retirement's vault revocation fails; the identity still retires.
	adapter.mu.Lock()
	adapter.failRevoke = errors.New("vault offline")
	adapter.mu.Unlock()
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: "payments-api", Confirm: true}, now()); err != nil {
		t.Fatalf("Retire() error = %v", err)
	}
	adapter.mu.Lock()
	adapter.failRevoke = nil
	adapter.mu.Unlock()

	if _, err := store.Delete(context.Background(), protocol.DeleteRequest{ID: "payments-api", Confirm: true}, now()); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if len(adapter.revoked) == 0 {
		t.Fatal("the delete did not re-revoke the vault copy the retirement missed")
	}
}

func TestDeleteIsSingleWinnerUnderConcurrency(t *testing.T) {
	adapter := &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}
	store := testStore(t, adapter)
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: "payments-api", Confirm: true}, now()); err != nil {
		t.Fatalf("Retire() error = %v", err)
	}

	const racers = 8
	var wg sync.WaitGroup
	results := make(chan error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Delete(context.Background(), protocol.DeleteRequest{ID: "payments-api", Confirm: true}, now())
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	var wins, losses int
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrNotFound):
			losses++
		default:
			t.Fatalf("unexpected delete error = %v", err)
		}
	}
	if wins != 1 || losses != racers-1 {
		t.Fatalf("delete outcomes = (%d wins, %d losses), want (1, %d)", wins, losses, racers-1)
	}
	if _, ok := store.Get("payments-api"); ok {
		t.Fatal("the record survived the winning delete")
	}
}
