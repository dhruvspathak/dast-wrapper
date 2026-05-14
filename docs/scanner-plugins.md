# Scanner Plugin Contract

Scanners are plugins, not orchestration logic.

Each scanner implements `app.scanners.base.ScannerPlugin`:

- `start_scan(target: ScanTarget) -> str`
- `get_status(scanner_scan_id: str) -> int`
- `get_findings(scanner_scan_id: str) -> list[ScannerFinding]`

Before persistence, every `ScannerFinding` is normalized through `ScannerPlugin.normalize_finding`.

Scanner-specific fields belong in `Finding.raw` only. Orchestration, replay, authorization validation, AI triage, and reporting consume canonical models from `app.schemas.canonical`.

Required flow:

```text
scanner output
  -> canonical Finding
  -> ReplayResult
  -> ValidationResult
  -> AI triage
  -> ReportArtifact
```

Do not add scanner-specific branches to worker orchestration. Register new scanners through `app.scanners.registry`.
