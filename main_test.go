package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackIntelligence)
}

func TestScanFindsAuthCluster(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CASE-001")
	if len(found) == 0 {
		t.Fatal("expected at least one CASE-001 (auth cluster) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityMedium {
			t.Errorf("CASE-001 severity should be MEDIUM, got %v", f.GetSeverity())
		}
		if f.GetConfidence() != sdk.ConfidenceHigh {
			t.Errorf("CASE-001 confidence should be HIGH, got %v", f.GetConfidence())
		}
		if f.GetLocation() == nil {
			t.Error("finding must include a location")
		}
		count, err := strconv.Atoi(f.GetMetadata()["indicator_count"])
		if err != nil || count < clusterThreshold {
			t.Errorf("CASE-001 should have at least %d indicators, got %s", clusterThreshold, f.GetMetadata()["indicator_count"])
		}
		if f.GetMetadata()["category"] != "auth" {
			t.Errorf("CASE-001 category should be 'auth', got %q", f.GetMetadata()["category"])
		}
	}
}

func TestScanFindsErrorHandlingCluster(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CASE-002")
	if len(found) == 0 {
		t.Fatal("expected at least one CASE-002 (error handling cluster) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityMedium {
			t.Errorf("CASE-002 severity should be MEDIUM, got %v", f.GetSeverity())
		}
		if f.GetMetadata()["category"] != "error_handling" {
			t.Errorf("CASE-002 category should be 'error_handling', got %q", f.GetMetadata()["category"])
		}
	}
}

func TestScanFindsInjectionCluster(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CASE-003")
	if len(found) == 0 {
		t.Fatal("expected at least one CASE-003 (injection cluster) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityHigh {
			t.Errorf("CASE-003 severity should be HIGH, got %v", f.GetSeverity())
		}
		if f.GetConfidence() != sdk.ConfidenceHigh {
			t.Errorf("CASE-003 confidence should be HIGH, got %v", f.GetConfidence())
		}
	}
}

func TestScanFindsConfigDriftCluster(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CASE-004")
	if len(found) == 0 {
		t.Fatal("expected at least one CASE-004 (config drift cluster) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityLow {
			t.Errorf("CASE-004 severity should be LOW, got %v", f.GetSeverity())
		}
	}
}

func TestScanBundlesMultipleIndicators(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	for _, f := range resp.GetFindings() {
		countStr, ok := f.GetMetadata()["indicator_count"]
		if !ok {
			t.Error("finding must include indicator_count metadata")
			continue
		}
		count, err := strconv.Atoi(countStr)
		if err != nil {
			t.Errorf("indicator_count should be numeric, got %q", countStr)
			continue
		}
		if count < clusterThreshold {
			t.Errorf("bundled finding should have at least %d indicators, got %d", clusterThreshold, count)
		}
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
