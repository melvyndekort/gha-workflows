#!/usr/bin/env python3
"""
Structural audit: find Terraform values that originate from a secret source and
land in a resource argument the provider does NOT mark sensitive.

Why this matters
----------------
Terraform redacts plan output based on the SINK, not the source. Two verified
facts drive this script:

  1. `sensitive = true` on an output does NOT survive `terraform_remote_state`.
     Outputs are serialised to state without the flag, so a consumer reads them
     as ordinary strings. Verified with a real plan: a value marked sensitive in
     the producer printed in full in the consumer's plan.

  2. `data.aws_kms_secrets.*.plaintext` IS provider-marked sensitive, and the
     taint DOES propagate through yamldecode(), nested attribute access and
     string interpolation. Verified with a real plan.

So: KMS-sourced values are safe wherever they land. Remote-state-sourced values
are safe ONLY if the attribute they land in is itself provider-sensitive
(e.g. aws_ssm_parameter.value). Anything else prints in plaintext -- and on a
public repo, a plan comment publishes it.

Usage
-----
  audit_plan_leaks.py --schemas schemas/ --repos extracted/ [--json out.json]

`--schemas` holds `<provider>.json` files from `terraform providers schema -json`.
`--repos` holds extracted repo tarballs (any depth; *.tf files are discovered).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import defaultdict

# --- source patterns -------------------------------------------------------

# Values whose sensitivity does NOT survive the hop: outputs lose the flag when
# serialised to state, so the consumer sees a plain string.
RE_REMOTE_STATE = re.compile(
    r"data\.terraform_remote_state\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)"
)
# Provider-sensitive at the source, and the taint propagates. Safe anywhere.
RE_KMS_LOCAL = re.compile(r"local\.secrets\b")
RE_KMS_DIRECT = re.compile(r"data\.aws_kms_secrets\.[A-Za-z0-9_-]+\.plaintext")

# --- HCL shapes we care about ---------------------------------------------

RE_RESOURCE_HEAD = re.compile(r'^\s*resource\s+"([A-Za-z0-9_]+)"\s+"([A-Za-z0-9_-]+)"\s*\{')
RE_OUTPUT_HEAD = re.compile(r'^\s*output\s+"([A-Za-z0-9_-]+)"\s*\{')
RE_PROVIDER_HEAD = re.compile(r'^\s*provider\s+"([A-Za-z0-9_]+)"\s*\{')
RE_LOCALS_HEAD = re.compile(r"^\s*locals\s*\{")
# `foo = <expr>` or `foo {` -- capture the assigned attribute name
RE_ASSIGN = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$")
RE_SENSITIVE_TRUE = re.compile(r"^\s*sensitive\s*=\s*true\s*$")


def load_schemas(schema_dir: pathlib.Path) -> dict[str, dict]:
    """Map resource type -> {attribute: sensitive_bool} from provider schemas."""
    sens: dict[str, dict[str, bool]] = {}
    for path in sorted(schema_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            print(f"warn: {path.name} is not valid JSON, skipped", file=sys.stderr)
            continue
        for _provider, pschema in data.get("provider_schemas", {}).items():
            for rtype, rschema in pschema.get("resource_schemas", {}).items():
                attrs = rschema.get("block", {}).get("attributes", {})
                table = sens.setdefault(rtype, {})
                for attr, meta in attrs.items():
                    table[attr] = bool(meta.get("sensitive", False))
                # nested blocks: flatten one level, enough for the shapes in use
                for bname, bmeta in rschema.get("block", {}).get("block_types", {}).items():
                    for attr, meta in bmeta.get("block", {}).get("attributes", {}).items():
                        table[f"{bname}.{attr}"] = bool(meta.get("sensitive", False))
    return sens


def classify_source(expr: str) -> str | None:
    """Return 'remote_state', 'kms', or None for an expression."""
    if RE_REMOTE_STATE.search(expr):
        return "remote_state"
    if RE_KMS_DIRECT.search(expr) or RE_KMS_LOCAL.search(expr):
        return "kms"
    return None


def audit_file(path: pathlib.Path, sens: dict[str, dict[str, bool]]) -> list[dict]:
    """Walk a .tf file tracking which block each assignment sits in."""
    findings: list[dict] = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return findings

    ctx_kind: str | None = None   # 'resource' | 'output' | 'provider' | 'locals'
    ctx_type = ""                 # resource type, e.g. aws_ssm_parameter
    ctx_name = ""
    depth = 0
    output_is_sensitive: dict[str, bool] = {}
    pending: list[dict] = []      # findings in an output block, resolved at close

    for lineno, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].split("//", 1)[0]

        if ctx_kind is None:
            m = RE_RESOURCE_HEAD.match(line)
            if m:
                ctx_kind, ctx_type, ctx_name = "resource", m.group(1), m.group(2)
                depth = line.count("{") - line.count("}")
                continue
            m = RE_OUTPUT_HEAD.match(line)
            if m:
                ctx_kind, ctx_type, ctx_name = "output", "", m.group(1)
                depth = line.count("{") - line.count("}")
                pending = []
                continue
            m = RE_PROVIDER_HEAD.match(line)
            if m:
                ctx_kind, ctx_type, ctx_name = "provider", m.group(1), m.group(1)
                depth = line.count("{") - line.count("}")
                continue
            if RE_LOCALS_HEAD.match(line):
                ctx_kind, ctx_type, ctx_name = "locals", "", ""
                depth = line.count("{") - line.count("}")
            continue

        # inside a block
        depth += line.count("{") - line.count("}")

        if ctx_kind == "output" and RE_SENSITIVE_TRUE.match(line):
            output_is_sensitive[ctx_name] = True

        m = RE_ASSIGN.match(line)
        if m:
            attr, expr = m.group(1), m.group(2)
            origin = classify_source(expr)
            if origin:
                rec = {
                    "file": str(path),
                    "line": lineno,
                    "block": ctx_kind,
                    "type": ctx_type,
                    "name": ctx_name,
                    "attribute": attr,
                    "origin": origin,
                    "expr": expr[:160],
                }
                if ctx_kind == "output":
                    pending.append(rec)
                else:
                    findings.append(rec)

        if depth <= 0:
            if ctx_kind == "output":
                marked = output_is_sensitive.get(ctx_name, False)
                for rec in pending:
                    rec["output_sensitive"] = marked
                    findings.append(rec)
                pending = []
            ctx_kind, ctx_type, ctx_name, depth = None, "", "", 0

    # attach sink sensitivity
    for rec in findings:
        if rec["block"] == "resource":
            table = sens.get(rec["type"])
            if table is None:
                rec["sink_sensitive"] = None  # schema unknown
            else:
                rec["sink_sensitive"] = table.get(rec["attribute"], False)
        elif rec["block"] == "output":
            # An output only redacts its OWN plan display; the flag is lost on
            # the next remote_state hop, so it is not a real containment.
            rec["sink_sensitive"] = rec.get("output_sensitive", False)
        elif rec["block"] == "provider":
            # Provider arguments are not rendered in plan output.
            rec["sink_sensitive"] = True
        else:
            rec["sink_sensitive"] = False
    return findings


def verdict(rec: dict) -> str:
    """LEAK / SAFE / UNKNOWN for one finding."""
    if rec["origin"] == "kms":
        return "SAFE"          # provider-sensitive at source, taint propagates
    if rec["block"] == "provider":
        return "SAFE"          # not rendered
    if rec["sink_sensitive"] is None:
        return "UNKNOWN"       # provider schema not available
    if rec["sink_sensitive"]:
        return "SAFE"          # sink redacts it
    # Remote-state value landing in a non-sensitive sink: prints in plaintext.
    # Whether that MATTERS depends on the producer -- an output the producer
    # marked `sensitive = true` is secret material; a zone id or bucket name is
    # not. `secret_source` is filled in by main() from the producer scan.
    return "LEAK" if rec.get("secret_source") else "COSMETIC"


def scan_sensitive_outputs(repos_dir: pathlib.Path) -> set[str]:
    """Collect output names any repo declares `sensitive = true`.

    These lose their flag crossing `terraform_remote_state`, so a consumer
    reading one gets an unmarked string -- the case that actually leaks.
    """
    names: set[str] = set()
    block = re.compile(r'output\s+"([A-Za-z0-9_-]+)"\s*\{(.*?)\n\}', re.S)
    for tf in repos_dir.rglob("*.tf"):
        try:
            txt = tf.read_text(errors="replace")
        except OSError:
            continue
        for m in block.finditer(txt):
            if re.search(r"sensitive\s*=\s*true", m.group(2)):
                names.add(m.group(1))
    return names


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schemas", required=True, type=pathlib.Path)
    ap.add_argument("--repos", required=True, type=pathlib.Path)
    ap.add_argument("--json", type=pathlib.Path)
    args = ap.parse_args()

    sens = load_schemas(args.schemas)
    if not sens:
        print("error: no resource schemas loaded", file=sys.stderr)
        return 2
    secret_outputs = scan_sensitive_outputs(args.repos)
    print(f"loaded schemas for {len(sens)} resource types")
    print(f"found {len(secret_outputs)} output name(s) declared sensitive by a producer\n")

    by_repo: dict[str, list[dict]] = defaultdict(list)
    for tf in sorted(args.repos.rglob("*.tf")):
        parts = tf.parts
        repo = "?"
        for p in parts:
            if p.startswith("x_"):
                repo = p[2:]
                break
        for rec in audit_file(tf, sens):
            rec["repo"] = repo
            m = RE_REMOTE_STATE.search(rec["expr"])
            rec["secret_source"] = bool(m and m.group(2) in secret_outputs)
            rec["verdict"] = verdict(rec)
            by_repo[repo].append(rec)

    leaks = unknowns = safe = cosmetic = 0
    for repo in sorted(by_repo):
        recs = by_repo[repo]
        bad = [r for r in recs if r["verdict"] == "LEAK"]
        unk = [r for r in recs if r["verdict"] == "UNKNOWN"]
        safe += sum(1 for r in recs if r["verdict"] == "SAFE")
        cosmetic += sum(1 for r in recs if r["verdict"] == "COSMETIC")
        leaks += len(bad)
        unknowns += len(unk)
        if not bad and not unk:
            print(f"  OK       {repo}  ({len(recs)} secret-flow(s), none secret-bearing)")
            continue
        print(f"  REVIEW   {repo}")
        for r in bad + unk:
            loc = pathlib.Path(r["file"]).name
            print(
                f"      [{r['verdict']}] {loc}:{r['line']}  "
                f"{r['block']} {r['type']}.{r['name']}.{r['attribute']}"
            )
            print(f"                 {r['expr']}")

    print(
        f"\nsummary: {leaks} LEAK, {unknowns} UNKNOWN, "
        f"{cosmetic} COSMETIC (non-secret ids/names), {safe} SAFE "
        f"across {len(by_repo)} repo(s)"
    )
    if args.json:
        args.json.write_text(
            json.dumps(
                {r: by_repo[r] for r in sorted(by_repo)}, indent=2, sort_keys=True
            )
        )
        print(f"wrote {args.json}")
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
