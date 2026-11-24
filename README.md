# Mobile Manifest Auditor

An offline Python tool for reviewing an Android app's `AndroidManifest.xml` before release. It flags risky permissions and configuration choices, then produces a JSON report with evidence and remediation guidance.

## What it demonstrates

- Static security review of an Android manifest using Python's XML parser
- Risk ranking with explicit evidence and actionable recommendations
- Awareness of exported components, cleartext traffic, backup settings, and permissions
- A privacy-minded workflow that never installs or runs the application

## Quick start

Requires Python 3.10 or newer. No third-party packages are needed.

```bash
python audit.py AndroidManifest.xml
python audit.py AndroidManifest.xml --output report.json
```

## Checks included

- High-risk permissions such as SMS, contacts, call logs, and broad storage access
- `android:usesCleartextTraffic="true"`
- `android:allowBackup="true"`
- Components exposed with `android:exported="true"`
- Components with intent filters that omit an explicit `android:exported` value

## Sample findings

The included sample manifest intentionally contains several issues. The tool should report findings such as exported activities and cleartext traffic with severity, XML element, evidence, and suggested remediation. This makes it suitable for a code-review discussion or a simple CI pre-check.

## Scope and limitations

This is a lightweight static check, not a replacement for a full mobile application assessment or platform tooling. It analyzes only the manifest supplied to it; it does not inspect bytecode, network behavior, third-party SDKs, or runtime permissions. Findings require human review because legitimate apps may need some flagged permissions or exported components.
