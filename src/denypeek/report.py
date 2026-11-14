"""Text and JSON output. Only fixed-prefix previews, lengths and fingerprints: never a full
secret, and no characters at all of a secret whose rule has no fixed prefix."""

from __future__ import annotations

import json
from typing import Optional

from . import __version__
from .scan import ScanResult
from .sources import Home, safe_text

NOT_PROOF = (
    "This is best-effort detection of known key shapes, not proof that this machine is clean."
)
ROTATE = "Rotate every real key found here, whether or not you redact it."


def scan_json(result: ScanResult, home: Home) -> str:
    data = {
        "tool": "denypeek",
        "version": __version__,
        "home": str(home.root),
        "complete": not result.incomplete,
        "exit_code": result.exit_code,
        "files_scanned": len(result.files),
        "files_per_agent": result.per_agent(),
        "findings": [
            {
                "agent": f.agent,
                "file": str(f.path),
                "line": f.line,
                "rule": f.rule,
                "preview": f.preview,
                "length": f.length,
                "fingerprint": f.fingerprint,
            }
            for f in result.findings
        ],
        "incomplete": [
            {"file": str(p.path), "where": p.where, "reason": p.reason} for p in result.incomplete
        ],
        "notes": [
            {"file": str(p.path), "where": p.where, "reason": p.reason} for p in result.notes
        ],
        "disclaimer": NOT_PROOF,
    }
    # ASCII only: every control, bidi or other non-ASCII character in a path is written as a
    # \\u escape, so the raw JSON is safe to show, and a JSON parser still gets the exact path.
    return json.dumps(data, indent=2, ensure_ascii=True)


def shown_key(preview: Optional[str], length: int, fp: str) -> str:
    """`AKIA… (20 chars)  fp 1a2b3c4d`; with no fixed prefix, no characters at all."""
    lead = f"{preview} " if preview else ""
    return f"{lead}({length} chars)  fp {fp}"


def _loc(home: Home, path, where: str) -> str:
    shown = home.display(path)
    return f"{shown}:{safe_text(where)}" if where else shown


def scan_text(result: ScanResult, home: Home) -> str:
    out = ["denypeek scan: offline, nothing leaves this machine."]
    per = result.per_agent()
    agents = ", ".join(f"{a} {n}" for a, n in sorted(per.items())) or "no history files found"
    out.append(f"Scanned {len(result.files)} file(s): {agents}.")

    if result.findings:
        out += ["", f"Possible secrets ({len(result.findings)}):"]
        for f in result.findings:
            out.append(
                f"  {f.agent:<7} {_loc(home, f.path, f.line)}  {f.rule}  "
                f"{shown_key(f.preview, f.length, f.fingerprint)}"
            )
    if result.incomplete:
        out += ["", f"NOT fully checked ({len(result.incomplete)}). Secrets here may be missed:"]
        for p in result.incomplete:
            out.append(f"  {_loc(home, p.path, p.where)}: {safe_text(p.reason)}")
    if result.notes:
        out += ["", f"Notes ({len(result.notes)}):"]
        for p in result.notes:
            out.append(f"  {_loc(home, p.path, p.where)}: {safe_text(p.reason)}")

    out.append("")
    if result.findings:
        out.append(f"Found {len(result.findings)} possible secret(s). {ROTATE}")
        out.append("To scrub them from history: denypeek redact (keeps a backup).")
    else:
        out.append("No known key shapes found.")
    if not result.files:
        out.append(
            f"No agent history found under {home.display(home.root)}; if that is not your "
            "home folder, check --home."
        )
    if result.incomplete:
        out.append("The scan was incomplete (exit code 2): see the list above.")
    out.append(NOT_PROOF)
    return "\n".join(out)
