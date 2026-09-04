package provider

import (
	"context"
	"testing"

	"github.com/mutandae/mutandae/pkg/protocol"
)

type planningCloudStub struct {
	stubAdapter
	plannedRotate int
	plannedRetire int
}

func (s *planningCloudStub) PlanRotateIdentity(_ context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	s.plannedRotate++
	return []protocol.PlannedOperation{{Op: s.kind + ".rotate", Identity: identity.Name, Detail: "rotate"}}, nil
}

func (s *planningCloudStub) PlanRetireIdentity(_ context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	s.plannedRetire++
	return []protocol.PlannedOperation{{Op: s.kind + ".retire", Identity: identity.Name, Detail: "retire"}}, nil
}

func TestMultiCloudRoutesDryRunPlansByProviderBinding(t *testing.T) {
	aws := &planningCloudStub{stubAdapter: stubAdapter{kind: "aws-iam"}}
	gcp := &planningCloudStub{stubAdapter: stubAdapter{kind: "gcp-iam"}}
	multi, err := NewMultiProvider(aws, gcp)
	if err != nil {
		t.Fatalf("NewMultiProvider: %v", err)
	}
	identity := identityOf("gcp-iam", "gcp-identity")
	rotate, err := multi.PlanRotateIdentity(context.Background(), identity)
	if err != nil {
		t.Fatalf("PlanRotateIdentity: %v", err)
	}
	if len(rotate) != 1 || rotate[0].Op != "gcp-iam.rotate" {
		t.Fatalf("rotate plan = %+v, want gcp route", rotate)
	}
	if aws.plannedRotate != 0 || gcp.plannedRotate != 1 {
		t.Fatalf("planner calls = aws %d, gcp %d", aws.plannedRotate, gcp.plannedRotate)
	}
	retire, err := multi.PlanRetireIdentity(context.Background(), identity)
	if err != nil {
		t.Fatalf("PlanRetireIdentity: %v", err)
	}
	if len(retire) != 1 || retire[0].Op != "gcp-iam.retire" {
		t.Fatalf("retire plan = %+v, want gcp route", retire)
	}
	if gcp.plannedRetire != 1 {
		t.Fatalf("gcp retire planner calls = %d, want 1", gcp.plannedRetire)
	}
}
