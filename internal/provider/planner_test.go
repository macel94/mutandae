package provider

import (
	"context"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func TestSimulatorPlannersReturnProviderTruthfulPlans(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		identity  func() (protocol.MachineIdentity, error)
		rotateOps []string
		retireOp  string
	}{
		{
			name: "azure",
			identity: func() (protocol.MachineIdentity, error) {
				identities, err := NewSimulator("tenant", now, DemoScope()).Discover(context.Background())
				return identities[0], err
			},
			rotateOps: []string{"graph.addPassword", "graph.removePassword"},
			retireOp:  "graph.deleteApplication",
		},
		{
			name: "aws",
			identity: func() (protocol.MachineIdentity, error) {
				identities, err := NewAWSSimulator("account", "us-east-1", now, DemoScope()).Discover(context.Background())
				return identities[0], err
			},
			rotateOps: []string{"aws.create_access_key", "aws.revoke_old_access_key"},
			retireOp:  "aws.disable_user",
		},
		{
			name: "gcp",
			identity: func() (protocol.MachineIdentity, error) {
				identities, err := NewGCPSimulator("project", "us-central1", now, DemoScope()).Discover(context.Background())
				return identities[0], err
			},
			rotateOps: []string{"gcp.create_service_account_key", "gcp.delete_key"},
			retireOp:  "gcp.delete_key",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			identity, err := test.identity()
			if err != nil {
				t.Fatalf("discover identity: %v", err)
			}
			var planner interface {
				PlanRotateIdentity(context.Context, protocol.MachineIdentity) ([]protocol.PlannedOperation, error)
				PlanRetireIdentity(context.Context, protocol.MachineIdentity) ([]protocol.PlannedOperation, error)
			}
			switch test.name {
			case "azure":
				planner = NewSimulator("tenant", now, DemoScope())
			case "aws":
				planner = NewAWSSimulator("account", "us-east-1", now, DemoScope())
			case "gcp":
				planner = NewGCPSimulator("project", "us-central1", now, DemoScope())
			}
			rotate, err := planner.PlanRotateIdentity(context.Background(), identity)
			if err != nil {
				t.Fatalf("PlanRotateIdentity: %v", err)
			}
			if got := operationNames(rotate); !sameStrings(got, test.rotateOps) {
				t.Fatalf("rotate operations = %v, want %v", got, test.rotateOps)
			}
			retire, err := planner.PlanRetireIdentity(context.Background(), identity)
			if err != nil {
				t.Fatalf("PlanRetireIdentity: %v", err)
			}
			if len(retire) != 1 || retire[0].Op != test.retireOp {
				t.Fatalf("retire operations = %v, want %s", operationNames(retire), test.retireOp)
			}
			for _, operation := range append(rotate, retire...) {
				if err := protocol.ValidatePlannedOperation(&operation); err != nil {
					t.Errorf("invalid operation %+v: %v", operation, err)
				}
			}
		})
	}
}

func TestRealPlannerOperationSequencesAreStaticAndScoped(t *testing.T) {
	ctx := context.Background()
	aws, err := NewAWSAdapter(AWSAdapterConfig{AccountID: "account", AccessKeyID: "access", SecretKey: "secret", Scope: DemoScope()})
	if err != nil {
		t.Fatalf("NewAWSAdapter: %v", err)
	}
	defer aws.Close()
	awsRotate, err := aws.PlanRotate(ctx, "mutandae-demo-orders")
	if err != nil {
		t.Fatalf("AWS PlanRotate: %v", err)
	}
	if got := operationNames(awsRotate); !sameStrings(got, []string{"aws.delete_access_key", "aws.create_access_key", "aws.verify_access_key", "aws.delete_access_key"}) {
		t.Fatalf("AWS rotate operations = %v", got)
	}
	if _, err := aws.PlanRetire(ctx, "production-user"); err == nil {
		t.Fatal("AWS planner accepted an out-of-scope identity")
	}

	gcp, err := NewGCPAdapter(GCPAdapterConfig{ProjectID: "project", KeyJSON: testGCPKeyJSON(), Scope: DemoScope()})
	if err != nil {
		t.Fatalf("NewGCPAdapter: %v", err)
	}
	defer gcp.Close()
	gcpRotate, err := gcp.PlanRotate(ctx, "mutandae-demo-orders@project.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("GCP PlanRotate: %v", err)
	}
	if got := operationNames(gcpRotate); !sameStrings(got, []string{"gcp.delete_key", "gcp.create_service_account_key", "gcp.verify_service_account_key", "gcp.delete_key"}) {
		t.Fatalf("GCP rotate operations = %v", got)
	}
	if _, err := gcp.PlanRetire(ctx, "production@project.iam.gserviceaccount.com"); err == nil {
		t.Fatal("GCP planner accepted an out-of-scope identity")
	}

	azure := &AzureCloudAdapter{scope: DemoScope()}
	azureRotate, err := azure.PlanRotate(ctx, "mutandae-demo-orders")
	if err != nil {
		t.Fatalf("Azure PlanRotate: %v", err)
	}
	if got := operationNames(azureRotate); !sameStrings(got, []string{"graph.addPassword", "graph.removePassword"}) {
		t.Fatalf("Azure rotate operations = %v", got)
	}
	if _, err := azure.PlanRetire(ctx, "production-app"); err == nil {
		t.Fatal("Azure planner accepted an out-of-scope identity")
	}
}

func operationNames(operations []protocol.PlannedOperation) []string {
	names := make([]string, 0, len(operations))
	for _, operation := range operations {
		names = append(names, operation.Op)
	}
	return names
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
