package lifecycle

import (
	"context"
	"testing"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func TestRetiredIdentityLeavesActiveListButKeepsAuditUntilDelete(t *testing.T) {
	store := testStore(t, &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}})
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: "payments-api", Confirm: true, Reason: "eol"}, now()); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if identities := store.List(); len(identities) != 0 {
		t.Fatalf("active List() = %+v, want no retired identities", identities)
	}
	identities := store.ListIncludingRetired()
	if len(identities) != 1 || identities[0].ID != "payments-api" || identities[0].State != protocol.StateRetired {
		t.Fatalf("ListIncludingRetired() = %+v, want the retired identity", identities)
	}
	events, ok := store.Events("payments-api")
	if !ok || len(events) == 0 || events[0].Type != protocol.EventIdentityRetired {
		t.Fatalf("retired events = (%v, %v), want retained identity.retired audit", ok, events)
	}
	if _, err := store.Delete(context.Background(), protocol.DeleteRequest{ID: "payments-api", Confirm: true}, now()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if identities := store.ListIncludingRetired(); len(identities) != 0 {
		t.Fatalf("inventory after delete = %+v, want empty", identities)
	}
}
