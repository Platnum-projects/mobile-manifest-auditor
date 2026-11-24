#!/usr/bin/env python3
"""Perform a lightweight, offline Android manifest security review."""
from __future__ import annotations
import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID = "{http://schemas.android.com/apk/res/android}"
RISKY_PERMISSIONS = {
    "android.permission.READ_SMS": ("high", "Avoid access to SMS unless it is essential and clearly disclosed."),
    "android.permission.SEND_SMS": ("high", "Use a trusted system flow instead of requesting direct SMS access."),
    "android.permission.READ_CONTACTS": ("medium", "Request contacts access only at the moment it is needed and minimize stored data."),
    "android.permission.READ_CALL_LOG": ("high", "Remove call-log access unless the core feature requires it."),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("high", "Prefer scoped storage and request only the files the feature needs."),
    "android.permission.ACCESS_FINE_LOCATION": ("medium", "Use approximate location when precise location is unnecessary."),
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def flag(severity: str, check: str, message: str, element: str, evidence: str, fix: str) -> dict:
    return {"severity": severity, "check": check, "message": message,
            "element": element, "evidence": evidence, "recommendation": fix}


def audit(path: Path) -> list[dict]:
    root = ET.parse(path).getroot()
    findings = []
    app = root.find("application")
    if app is None:
        raise ValueError("manifest has no application element")

    for permission in root.findall("uses-permission"):
        name = permission.get(ANDROID + "name", "")
        if name in RISKY_PERMISSIONS:
            severity, fix = RISKY_PERMISSIONS[name]
            findings.append(flag(severity, "risky-permission", "Sensitive permission requested",
                                 "uses-permission", name, fix))

    if app.get(ANDROID + "usesCleartextTraffic", "false").lower() == "true":
        findings.append(flag("high", "cleartext-traffic", "Application allows unencrypted HTTP traffic",
                             "application", "android:usesCleartextTraffic=true",
                             "Disable cleartext traffic and use TLS for network connections."))
    if app.get(ANDROID + "allowBackup", "true").lower() == "true":
        findings.append(flag("medium", "backup-enabled", "Application data backup is enabled",
                             "application", "android:allowBackup=true or unspecified",
                             "Review backup contents and exclude secrets or sensitive records."))

    component_tags = {"activity", "activity-alias", "service", "receiver", "provider"}
    for component in list(app):
        if component.tag not in component_tags:
            continue
        name = component.get(ANDROID + "name", "(unnamed component)")
        exported = component.get(ANDROID + "exported")
        has_intent_filter = component.find("intent-filter") is not None
        if exported == "true":
            findings.append(flag("high", "exported-component", "Component is exposed to other apps",
                                 component.tag, name,
                                 "Set exported=false unless external access is required; protect required entry points."))
        elif has_intent_filter and exported is None:
            findings.append(flag("medium", "implicit-export", "Component has an intent filter without an explicit exported value",
                                 component.tag, name,
                                 "Declare android:exported explicitly and confirm the intended access boundary."))

    return sorted(findings, key=lambda item: (SEVERITY_ORDER[item["severity"]], item["check"], item["element"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="path to AndroidManifest.xml")
    parser.add_argument("--output", type=Path, help="write the JSON report to a file")
    args = parser.parse_args()
    try:
        findings = audit(args.manifest)
    except (OSError, ET.ParseError, ValueError) as exc:
        print(f"Could not audit manifest: {exc}", file=sys.stderr)
        return 2
    report = {"file": args.manifest.name, "finding_count": len(findings), "findings": findings}
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote {len(findings)} finding(s) to {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
