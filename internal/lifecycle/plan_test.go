package lifecycle

import (
	"context"
	"reflect"
	"testing"

	"github.com/mutandae/mutandae/pkg/protocol"
)

type dryRunPlannerAdapter struct {
	*fakeAdapter
	rotatePlans int
	retirePlans int
}

func (a *dryRunPlannerAdapter) PlanRotateIdentity(_ context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	a.rotatePlans++
	return []protocol.PlannedOperation{{
		Op: "test.create_credential", Identity: identity.Name, Detail: "create a replacement credential", Reversible: true,
	}}, nil
}

func (a *dryRunPlannerAdapter) PlanRetireIdentity(_ context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	a.retirePlans++
	return []protocol.PlannedOperation{{
		Op: "test.revoke_credential", Identity: identity.Name, Detail: "revoke the governed credential", Destructive: true,
	}}, nil
}

func TestRotateDryRunUsesPlannerWithoutChangingLifecycleState(t *testing.T) {
	adapter := &dryRunPlannerAdapter{fakeAdapter: &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}}
	store := testStore(t, adapter)
	before, _ := store.Get("payments-api")
	beforeEvents, _ := store.Events("payments-api")
	beforeRuns, _ := store.Runs("payments-api")

	response, err := store.Rotate(context.Background(), protocol.RotateRequest{ID: "payments-api", DryRun: true}, now())
	if err != nil {
		t.Fatalf("Rotate dry-run: %v", err)
	}
	if response.Plan == nil || !response.Plan.DryRun || len(response.Plan.Operations) != 1 {
		t.Fatalf("response plan = %+v, want one dry-run operation", response.Plan)
	}
	if adapter.rotatePlans != 1 || adapter.rotations != 0 {
		t.Fatalf("planner/provider calls = %d/%d, want 1/0", adapter.rotatePlans, adapter.rotations)
	}
	after, _ := store.Get("payments-api")
	afterEvents, _ := store.Events("payments-api")
	afterRuns, _ := store.Runs("payments-api")
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("dry-run changed identity: before=%+v after=%+v", before, after)
	}
	if len(afterEvents) != len(beforeEvents) || len(afterRuns) != len(beforeRuns) {
		t.Fatalf("dry-run changed lifecycle evidence: events %d->%d runs %d->%d", len(beforeEvents), len(afterEvents), len(beforeRuns), len(afterRuns))
	}
}

func TestRetireDryRunDoesNotRequireConfirmationOrChangeLifecycleState(t *testing.T) {
	adapter := &dryRunPlannerAdapter{fakeAdapter: &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}}
	store := testStore(t, adapter)
	before, _ := store.Get("payments-api")
	beforeEvents, _ := store.Events("payments-api")

	response, err := store.Retire(context.Background(), protocol.RetireRequest{ID: "payments-api", DryRun: true}, now())
	if err != nil {
		t.Fatalf("Retire dry-run: %v", err)
	}
	if response.Plan == nil || !response.Plan.DryRun || len(response.Plan.Operations) != 1 {
		t.Fatalf("response plan = %+v, want one dry-run operation", response.Plan)
	}
	if adapter.retirePlans != 1 || len(adapter.retired) != 0 {
		t.Fatalf("planner/provider calls = %d/%d, want 1/0", adapter.retirePlans, len(adapter.retired))
	}
	after, _ := store.Get("payments-api")
	afterEvents, _ := store.Events("payments-api")
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("dry-run changed identity: before=%+v after=%+v", before, after)
	}
	if len(afterEvents) != len(beforeEvents) {
		t.Fatalf("dry-run changed events: %d->%d", len(beforeEvents), len(afterEvents))
	}
}
