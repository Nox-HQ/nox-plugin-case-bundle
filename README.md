# nox-plugin-case-bundle

**Bundle related security indicators into clustered findings for faster triage.**

<!-- badges -->
![Track: Intelligence](https://img.shields.io/badge/track-Intelligence-teal)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8)

---

## Overview

`nox-plugin-case-bundle` groups related security indicators found in the same file into bundled findings. Instead of reporting individual low-signal detections, it identifies clusters of related issues -- multiple auth weaknesses in the same file, several error handling gaps in the same module, or numerous injection vectors in the same handler -- and bundles them into a single, higher-context finding. This approach reduces alert fatigue while surfacing systemic patterns that isolated findings would miss.

Individual security indicators often tell an incomplete story. A single `password ==` comparison might be intentional; three auth-related issues in the same file indicate a systemic problem. A single empty catch block is a minor oversight; four error handling gaps in the same module suggest the developer skipped error handling entirely. This plugin applies a cluster threshold (minimum 2 indicators of the same category per file) to separate noise from patterns that deserve investigation.

The plugin scans across four indicator categories: authentication weaknesses (password comparisons, session handling, JWT operations), error handling gaps (empty catch blocks, ignored errors, swallowed exceptions), injection risks (string-concatenated SQL, `eval()`, command injection, innerHTML assignment), and configuration drift (hardcoded values, TODO comments about config, disabled TLS verification). Each category uses language-specific regex patterns for Go, Python, JavaScript, and TypeScript.

## Use Cases

### Security Triage Acceleration

Your security team receives hundreds of individual findings from static analysis tools. Most are low-severity, and reviewing them individually is impractical. This plugin clusters related indicators by category within each file, producing a smaller set of higher-signal findings. A file with three injection vectors becomes a single "Injection risk cluster" finding with all three locations documented in the metadata.

### Auth Implementation Review

A developer implements login, session management, and password verification in a single authentication module. This plugin detects the cluster of auth-related patterns -- password comparisons, JWT operations, session handling -- and bundles them into a single finding. The bundled finding spans from the first to the last auth indicator, giving the reviewer the exact line range to audit.

### Error Handling Quality Assessment

Your codebase has files where errors are systematically ignored -- empty catch blocks, discarded error returns, TODO comments about error handling. This plugin detects when multiple error handling gaps cluster in the same file and reports them as a single finding, highlighting files where error handling was likely deferred or intentionally skipped.

### Injection Surface Mapping

A handler file contains string-concatenated SQL queries, direct innerHTML assignments, and an `eval()` call. Individually, each is a concern; together, they indicate a file with no input sanitization discipline. This plugin bundles these injection vectors into a single high-severity finding with the count and locations of all detected vectors.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-case-bundle
   ```

2. **Create a test file** (`demo/handler.go`):

   ```go
   package main

   import (
       "database/sql"
       "fmt"
       "net/http"
   )

   var db *sql.DB

   func loginHandler(w http.ResponseWriter, r *http.Request) {
       username := r.FormValue("username")
       password := r.FormValue("password")

       // Auth indicators
       if password == "admin123" {
           session.Set("authenticated", true)
       }
       token := jwt.Parse(r.Header.Get("Authorization"))
       credentials.Validate(username, password)

       // Injection indicators
       query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", username)
       db.Exec("DELETE FROM sessions WHERE user = " + username)

       // Error handling indicators
       _, _ = db.Query(query)
       // TODO: handle error properly
   }
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/case-bundle demo/
   ```

4. **Review findings**

   ```
   nox-plugin-case-bundle: 3 findings

   CASE-001 [MEDIUM] Multiple auth-related issues clustered in same file
     (4 indicators found)
     demo/handler.go:16:20
     category: auth
     indicator_count: 4
     details: line 16: if password == "admin123" {; line 17: session.Set(
       "authenticated", true); line 19: token := jwt.Parse(r.Header.Get(
       "Authorization")); line 20: credentials.Validate(username, password)

   CASE-003 [HIGH] Injection risk cluster: multiple injection vectors in same
     handler (2 indicators found)
     demo/handler.go:23:24
     category: injection
     indicator_count: 2
     details: line 23: query := fmt.Sprintf("SELECT * FROM users WHERE
       name = '%s'", username); line 24: db.Exec("DELETE FROM sessions
       WHERE user = " + username)

   CASE-002 [MEDIUM] Error handling gaps cluster in same module
     (2 indicators found)
     demo/handler.go:27:28
     category: error_handling
     indicator_count: 2
     details: line 27: _, _ = db.Query(query); line 28: // TODO: handle
       error properly
   ```

## Rules

| ID | Description | Severity | Confidence |
|----|-------------|----------|------------|
| CASE-001 | Multiple auth-related issues clustered in same file | Medium | High |
| CASE-002 | Error handling gaps cluster in same module | Medium | Medium |
| CASE-003 | Injection risk cluster: multiple injection vectors in same handler | High | High |
| CASE-004 | Configuration drift cluster: multiple config issues in same file | Low | Medium |

### Cluster Threshold

A bundled finding is only emitted when **2 or more** indicators of the same category are detected in a single file. Files with only one indicator per category produce no findings.

### Auth Indicators (CASE-001)

| Language | Patterns |
|----------|----------|
| Go | `password ==`, `bcrypt.CompareHash`, `jwt.Parse`, `session.*`, `auth*.*()`, `Login()`, `Authenticate()`, `credentials.*`, `BasicAuth()` |
| Python | `password ==`, `check_password`, `authenticate()`, `login()`, `session[`, `jwt.decode`, `token ==`, `credentials.*`, `auth*.*()` |
| JavaScript/TypeScript | `password ===`, `bcrypt.compare`, `jwt.verify`, `jwt.sign`, `session.*`, `auth*.*()`, `login()`, `passport.*`, `credentials.*` |

### Error Handling Indicators (CASE-002)

| Language | Patterns |
|----------|----------|
| Go | Empty `if err != nil {}`, discarded error returns (`_ = foo()`), unhandled errors, TODO/ignore error comments |
| Python | `except: pass`, `except Exception: pass`, bare `except:`, TODO/ignore error comments |
| JavaScript/TypeScript | Empty `catch() {}`, `.catch(() => {})`, `.catch(() => null)`, TODO/ignore error comments |

### Injection Indicators (CASE-003)

| Language | Patterns |
|----------|----------|
| Go | `fmt.Sprintf` with SQL keywords, string concatenation in queries, `Exec(... +`, `template.HTML()`, `exec.Command(... +` |
| Python | `execute(... %`, `execute(... .format`, f-string SQL, `os.system()`, `subprocess.call(... shell=True)`, `eval()`, `exec()` |
| JavaScript/TypeScript | `query(... +`, `.innerHTML =`, `document.write()`, `eval()`, `child_process.*(... +`, `new Function()` |

### Configuration Drift Indicators (CASE-004)

| Language | Patterns |
|----------|----------|
| Go | TODO/FIXME config comments, hardcoded values, `InsecureSkipVerify: true`, `http.ListenAndServe(":`  |
| Python | TODO/FIXME config comments, hardcoded values, `DEBUG = True`, `ALLOWED_HOSTS = [... *` |
| JavaScript/TypeScript | TODO/FIXME config comments, hardcoded values, `NODE_TLS_REJECT_UNAUTHORIZED`, fallback env defaults |

## Supported Languages / File Types

| Language | Extensions | Detection Scope |
|----------|-----------|-----------------|
| Go | `.go` | Auth patterns, error handling, SQL injection, command injection, config drift |
| Python | `.py` | Auth patterns, exception handling, SQL injection, command execution, config drift |
| JavaScript | `.js` | Auth patterns, promise/catch handling, DOM injection, eval, config drift |
| TypeScript | `.ts` | Auth patterns, promise/catch handling, DOM injection, eval, config drift |

## Configuration

This plugin requires no configuration.

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| _None_ | This plugin has no environment variables | -- |

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-case-bundle
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-case-bundle.git
cd nox-plugin-case-bundle
go build -o nox-plugin-case-bundle .
```

## Development

```bash
# Build
go build ./...

# Run tests
go test ./...

# Run a specific test
go test ./... -run TestInjectionCluster

# Lint
golangci-lint run

# Run in Docker
docker build -t nox-plugin-case-bundle .
docker run --rm nox-plugin-case-bundle
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio.

**Scan pipeline:**

1. **Workspace walk** -- Recursively traverses the workspace root, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, and `.venv` directories. Only source files with supported extensions are processed.

2. **Indicator collection** -- Each source file is scanned line-by-line. Every line is tested against all indicator patterns for the file's extension. When a match is found, an `indicator` struct is created with the category, line number, and matched line content. Indicators are collected into a `map[string][]indicator` keyed by category.

3. **Cluster threshold evaluation** -- After scanning the entire file, each category's indicator list is checked against the cluster threshold (currently 2). Categories with fewer indicators than the threshold are discarded.

4. **Bundled finding emission** -- For categories that meet the threshold, a single finding is emitted with:
   - The finding spans from the first indicator's line to the last indicator's line
   - The description includes the indicator count
   - Metadata includes the language, indicator count, category, and a semicolon-separated details string with all indicator locations and content

5. **Output** -- Findings include all indicator details as metadata, enabling downstream tools to expand the bundle and examine individual indicators.

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-indicator-category`)
3. Write tests for new indicator detection patterns
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request

## License

Apache-2.0
