# SandboxReporting

Generate operational sandbox analysis reports from a WEB CSV export and a
SANDBOX_VERDICT CSV export.

The tool correlates WEB `Sandbox MD5` values with SANDBOX_VERDICT `File MD5`
values and uses WEB `Event Time` as the only download timestamp source.

## Usage

```bash
./sandbox_analysis_report.py WEB_log.csv SANDBOX_VERDICT_log.csv
```

The script writes three files in the current directory:

- `sandbox_analysis_report_details.csv`
- `sandbox_analysis_report_summary.txt`
- `sandbox_analysis_report.html`

## Report Logic

- Matched sandbox decisions use the latest WEB `Event Time` before the sandbox
  `Analysis Completed Time`.
- Cloud-known files without a sandbox verdict are reported as `known_by_cloud`
  with a `0s` decision duration.
- Files sent for analysis more than once before completion are reported as
  repeated sent-for-analysis events.
- Missing sandbox verdicts for sent-for-analysis files are reported as canceled
  or incomplete.
- Destination domains are derived from the WEB `URL` host and reported in top-25
  tables for worst sandbox release time, worst average sandbox release time, and
  highest block ratio.
- Timeline findings are grouped by UTC hour and include a static inline SVG
  chart in the HTML report for avg release, P90 release, and sandboxed file
  count. The text summary keeps the same data in ASCII tables.
- Block ratio is based on WEB policy action and blocked-policy fields. Repeated
  WEB events for the same MD5 count as one file, but any blocked event marks
  that file as blocked for the domain metric.
- User-specific report sections are intentionally omitted for privacy.

## Requirements

Python 3.10 or newer. No external Python packages are required.
