# Reachability Test Repository

A catalog of purpose-built applications for validating vulnerability reachability analysis. Each application is constructed to contain specific code patterns that correspond to known vulnerabilities (BDSAs/CVEs), providing controlled ground-truth cases that a reachability analysis system can be run against and its results verified.

## Purpose

Reachability analysis determines whether a vulnerability in a dependency is actually *reachable* through the application's own code — not just present in the dependency tree. This repository supports validation of that analysis by providing:

- **Positive test cases** — applications that intentionally implement vulnerable code patterns, where the expected result is `reachable: true`
- **Negative test cases** — applications that use a vulnerable dependency but do not invoke the vulnerable code paths, where the expected result is `reachable: false`

Each application targets one or more BDSAs and is written to cover the full range of pattern categories generated for each vulnerability signature: enabling/configuration APIs, dangerous instantiations, and direct invocation patterns.

## Repository Structure

```
/
├── README.md               # This file
├── manifest.json           # Index of all applications and their expected reachability outcomes
├── vertx-webapp/           # Positive test case — Vert.x web application (4 BDSAs)
│   ├── README.md
│   └── ...
└── <future-apps>/          # Additional positive and negative test cases
```

## Manifest

`manifest.json` at the root is the authoritative index of all applications in this repository. It records which BDSAs each application covers and the expected outcome for each, enabling automated validation of reachability analysis results.

### Structure

```json
{
    "applications": [
        {
            "app": "<app-name>",
            "path": "<relative-path>",
            "role": "positive | negative",
            "description": "<summary>",
            "bdsa": [
                {
                    "id": "<BDSA-ID>",
                    "cve": "<CVE-ID or null>",
                    "description": "<vulnerability summary>",
                    "expected_matches": [
                        {
                            "file": "<relative path to source file>",
                            "reachable": true
                        }
                    ]
                }
            ]
        }
    ]
}
```

### Fields

| Field | Description |
|---|---|
| `app` | Short identifier for the application |
| `path` | Path to the application directory relative to the repository root |
| `role` | `positive` — vulnerable patterns are present and should be matched; `negative` — vulnerable patterns are absent and should not be matched |
| `description` | Human-readable summary of what the application demonstrates |
| `bdsa[].id` | BDSA identifier |
| `bdsa[].cve` | Corresponding CVE identifier, or `null` if not yet assigned |
| `bdsa[].description` | Short description of the vulnerability |
| `expected_matches[].file` | Source file path (relative to the application root) expected to produce a match |
| `expected_matches[].reachable` | Expected reachability outcome for that file |

> The manifest is intentionally kept local and excluded from version control. See `.gitignore`.

## Applications

Each application has its own README documenting the specific vulnerabilities it covers, the patterns implemented, and instructions for building and running it.

| Application | Role | BDSAs Covered |
|---|---|---|
| [vertx-webapp](vertx-webapp/README.md) | Positive | BDSA-2023-2163, BDSA-2024-0760, BDSA-2025-14250, BDSA-2025-14251 |

## Adding a New Application

1. Create a new directory at the repository root for the application.
2. Implement the relevant vulnerable (or non-vulnerable) code patterns in the application source.
3. Add a `README.md` inside the application directory documenting the BDSAs covered and patterns implemented.
4. Update `manifest.json` with a new entry for the application, including its `role` and all `expected_matches`.
