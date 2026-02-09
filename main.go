package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// indicator represents a single detected indicator within a file,
// categorized for bundling purposes.
type indicator struct {
	Category string
	Line     int
	Detail   string
}

// indicatorPattern defines a compiled regex pattern for a specific indicator
// category, keyed by file extension.
type indicatorPattern struct {
	Category string
	Patterns map[string]*regexp.Regexp // extension -> compiled regex
}

// clusterThreshold is the minimum number of indicators of the same category
// required in a single file to trigger a bundled finding.
const clusterThreshold = 2

// --- Compiled regex patterns for indicator detection ---

var indicatorPatterns = []indicatorPattern{
	// Auth-related indicators for CASE-001
	{
		Category: "auth",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(password\s*==|password\s*!=|token\s*==|bcrypt\.CompareHash|jwt\.Parse|session\.\w+|auth\w*\.\w+\(|Login\(|Authenticate\(|credentials\.\w+|BasicAuth\()`),
			".py": regexp.MustCompile(`(?i)(password\s*==|password\s*!=|check_password|authenticate\(|login\(|session\[|jwt\.decode|token\s*==|credentials\.\w+|auth\w*\.\w+\()`),
			".js": regexp.MustCompile(`(?i)(password\s*===|password\s*!==|bcrypt\.compare|jwt\.verify|jwt\.sign|session\.\w+|auth\w*\.\w+\(|login\(|passport\.\w+|credentials\.\w+)`),
			".ts": regexp.MustCompile(`(?i)(password\s*===|password\s*!==|bcrypt\.compare|jwt\.verify|jwt\.sign|session\.\w+|auth\w*\.\w+\(|login\(|passport\.\w+|credentials\.\w+)`),
		},
	},
	// Error handling indicators for CASE-002
	{
		Category: "error_handling",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(if\s+err\s*!=\s*nil\s*\{[\s]*\}|_\s*,?\s*=\s*\w+\.\w+\(|err\s*=\s*\w+\.\w+\([^)]*\)\s*$|\/\/\s*TODO.*error|ignore.*error)`),
			".py": regexp.MustCompile(`(?i)(except:\s*$|except\s+Exception:\s*pass|except:\s*pass|\.write\([^)]*\)\s*$|#\s*TODO.*error|ignore.*error)`),
			".js": regexp.MustCompile(`(?i)(catch\s*\(\w*\)\s*\{\s*\}|\.catch\(\s*\(\)\s*=>\s*\{\s*\}\)|\.catch\(\s*\(\)\s*=>\s*null|\/\/\s*TODO.*error|ignore.*error)`),
			".ts": regexp.MustCompile(`(?i)(catch\s*\(\w*\)\s*\{\s*\}|\.catch\(\s*\(\)\s*=>\s*\{\s*\}\)|\.catch\(\s*\(\)\s*=>\s*null|\/\/\s*TODO.*error|ignore.*error)`),
		},
	},
	// Injection risk indicators for CASE-003
	{
		Category: "injection",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(fmt\.Sprintf\(.*SELECT|fmt\.Sprintf\(.*INSERT|fmt\.Sprintf\(.*UPDATE|fmt\.Sprintf\(.*DELETE|query\s*\+\s*|Exec\(.*\+|template\.HTML\(|exec\.Command\(.*\+)`),
			".py": regexp.MustCompile(`(?i)(execute\(.*%|execute\(.*\.format|f".*SELECT|f".*INSERT|os\.system\(|subprocess\.call\(.*shell=True|eval\(|exec\()`),
			".js": regexp.MustCompile(`(?i)(query\(.*\+|\.innerHTML\s*=|document\.write\(|eval\(|child_process\.\w+\(.*\+|new\s+Function\()`),
			".ts": regexp.MustCompile(`(?i)(query\(.*\+|\.innerHTML\s*=|document\.write\(|eval\(|child_process\.\w+\(.*\+|new\s+Function\()`),
		},
	},
	// Configuration drift indicators for CASE-004
	{
		Category: "config_drift",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(TODO\s*:?\s*.*config|FIXME\s*:?\s*.*config|hardcoded|hard.coded|magic.number|InsecureSkipVerify:\s*true|TLSClientConfig|http\.ListenAndServe\(":)`),
			".py": regexp.MustCompile(`(?i)(TODO\s*:?\s*.*config|FIXME\s*:?\s*.*config|hardcoded|hard.coded|magic.number|DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[.*\*)`),
			".js": regexp.MustCompile(`(?i)(TODO\s*:?\s*.*config|FIXME\s*:?\s*.*config|hardcoded|hard.coded|magic.number|NODE_TLS_REJECT_UNAUTHORIZED|process\.env\.\w+\s*\|\|\s*['"])`),
			".ts": regexp.MustCompile(`(?i)(TODO\s*:?\s*.*config|FIXME\s*:?\s*.*config|hardcoded|hard.coded|magic.number|NODE_TLS_REJECT_UNAUTHORIZED|process\.env\.\w+\s*\|\|\s*['"])`),
		},
	},
}

// supportedExtensions lists file extensions the case bundle scanner processes.
var supportedExtensions = map[string]bool{
	".go": true,
	".py": true,
	".js": true,
	".ts": true,
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

// categoryToRule maps indicator categories to their rule IDs, severities,
// confidences, and descriptions.
var categoryToRule = map[string]struct {
	RuleID      string
	Severity    pluginv1.Severity
	ConfLevel   pluginv1.Confidence
	Description string
}{
	"auth": {
		RuleID:      "CASE-001",
		Severity:    sdk.SeverityMedium,
		ConfLevel:   sdk.ConfidenceHigh,
		Description: "Multiple auth-related issues clustered in same file",
	},
	"error_handling": {
		RuleID:      "CASE-002",
		Severity:    sdk.SeverityMedium,
		ConfLevel:   sdk.ConfidenceMedium,
		Description: "Error handling gaps cluster in same module",
	},
	"injection": {
		RuleID:      "CASE-003",
		Severity:    sdk.SeverityHigh,
		ConfLevel:   sdk.ConfidenceHigh,
		Description: "Injection risk cluster: multiple injection vectors in same handler",
	},
	"config_drift": {
		RuleID:      "CASE-004",
		Severity:    sdk.SeverityLow,
		ConfLevel:   sdk.ConfidenceMedium,
		Description: "Configuration drift cluster: multiple config issues in same file",
	},
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/case-bundle", version).
		Capability("case-bundle", "Case and incident bundling for related security indicators").
		Tool("scan", "Scan source files and bundle related security indicators into clustered findings", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !supportedExtensions[ext] {
			return nil
		}

		return scanFileForClusters(resp, path, ext)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

// scanFileForClusters scans a single source file, collects indicators by
// category, and emits bundled findings when the cluster threshold is met.
func scanFileForClusters(resp *sdk.ResponseBuilder, filePath, ext string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil // skip unreadable files
	}
	defer f.Close()

	// Collect indicators by category.
	categoryIndicators := make(map[string][]indicator)

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for i := range indicatorPatterns {
			ip := &indicatorPatterns[i]
			pattern, ok := ip.Patterns[ext]
			if !ok {
				continue
			}
			if pattern.MatchString(line) {
				categoryIndicators[ip.Category] = append(categoryIndicators[ip.Category], indicator{
					Category: ip.Category,
					Line:     lineNum,
					Detail:   strings.TrimSpace(line),
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// Emit bundled findings for categories that meet the cluster threshold.
	for category, indicators := range categoryIndicators {
		if len(indicators) < clusterThreshold {
			continue
		}

		rule, ok := categoryToRule[category]
		if !ok {
			continue
		}

		firstLine := indicators[0].Line
		lastLine := indicators[len(indicators)-1].Line

		// Collect indicator details for the bundled description.
		details := make([]string, 0, len(indicators))
		for _, ind := range indicators {
			details = append(details, fmt.Sprintf("line %d: %s", ind.Line, ind.Detail))
		}

		resp.Finding(
			rule.RuleID,
			rule.Severity,
			rule.ConfLevel,
			fmt.Sprintf("%s (%d indicators found)", rule.Description, len(indicators)),
		).
			At(filePath, firstLine, lastLine).
			WithMetadata("language", extToLanguage(ext)).
			WithMetadata("indicator_count", fmt.Sprintf("%d", len(indicators))).
			WithMetadata("category", category).
			WithMetadata("details", strings.Join(details, "; ")).
			Done()
	}

	return nil
}

func extToLanguage(ext string) string {
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	default:
		return "unknown"
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-case-bundle: %v\n", err)
		os.Exit(1)
	}
}
