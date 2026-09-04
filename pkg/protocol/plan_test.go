package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDryRunRequestsRoundTripAndRejectNonBooleanJSON(t *testing.T) {
	var rotate RotateRequest
	if err := json.Unmarshal([]byte(`{"id":"identity-1","dry_run":true}`), &rotate); err != nil {
		t.Fatalf("decode rotate dry_run: %v", err)
	}
	if !rotate.DryRun {
		t.Fatal("rotate dry_run was not decoded")
	}
	var retire RetireRequest
	if err := json.Unmarshal([]byte(`{"id":"identity-1","confirm":false,"dry_run":true}`), &retire); err != nil {
		t.Fatalf("decode retire dry_run: %v", err)
	}
	if !retire.DryRun || retire.Confirm {
		t.Fatalf("retire request = %+v, want dry_run true and confirm false", retire)
	}
	for _, payload := range []string{
		`{"id":"identity-1","dry_run":"true"}`,
		`{"id":"identity-1","confirm":false,"dry_run":1}`,
	} {
		var target any
		if strings.Contains(payload, "confirm") {
			target = &RetireRequest{}
		} else {
			target = &RotateRequest{}
		}
		if err := json.Unmarshal([]byte(payload), target); err == nil {
			t.Errorf("decoded non-boolean dry_run payload %s", payload)
		}
	}
}

func TestValidatePlanRequiresStableReadOnlyShape(t *testing.T) {
	valid := Plan{
		DryRun: true,
		Operations: []PlannedOperation{{
			Op: "graph.addPassword", Identity: "identity-1", Detail: "add replacement", Reversible: true,
		}},
		ExpiresHint: "re-plan before applying",
	}
	if err := ValidatePlan(&valid); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
	for name, plan := range map[string]Plan{
		"not dry run":        {Operations: valid.Operations, ExpiresHint: valid.ExpiresHint},
		"missing operations": {DryRun: true, ExpiresHint: valid.ExpiresHint},
		"missing detail":     {DryRun: true, Operations: []PlannedOperation{{Op: "op", Identity: "id"}}, ExpiresHint: valid.ExpiresHint},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePlan(&plan); err == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
}

func TestDryRunRotateResponseOmitsExecutionRun(t *testing.T) {
	plan := Plan{
		DryRun:      true,
		Operations:  []PlannedOperation{{Op: "aws.create_access_key", Identity: "identity-1", Detail: "create replacement"}},
		ExpiresHint: "re-plan before applying",
	}
	payload, err := json.Marshal(RotateResponse{APIVersion: Version, Plan: &plan})
	if err != nil {
		t.Fatalf("marshal dry-run response: %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode dry-run response: %v", err)
	}
	if _, ok := document["rotation"]; ok {
		t.Fatalf("dry-run response serialized an execution rotation: %s", payload)
	}
	if _, ok := document["plan"]; !ok {
		t.Fatalf("dry-run response omitted plan: %s", payload)
	}
}
