#!/usr/bin/env python3
"""Derive the public Cloud API reference spec from the live msb-api OpenAPI spec.

Selects the organization API-key surface (operations authenticated with the
`api_key` scheme), drops operations the hosted Cloud does not yet support
publicly, rewrites implementation-oriented summaries into reader-facing
titles, and prunes unreferenced schemas. The result is checked in at
docs/api-reference/openapi.json and rendered by Mintlify.

Usage:
  scripts/sync-docs-openapi.py            # rewrite docs/api-reference/openapi.json
  scripts/sync-docs-openapi.py --check    # exit 1 if the checked-in spec is stale
  scripts/sync-docs-openapi.py --source /path/to/openapi.json
"""

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

LIVE_SPEC_URL = "https://api.microsandbox.dev/docs/openapi.json"
OUTPUT = Path(__file__).resolve().parent.parent / "docs" / "api-reference" / "openapi.json"

# Operations excluded even though they carry api_key auth. Keyed by
# (METHOD, path); the value documents why the operation is held back.
POLICY_EXCLUDE = {
    ("GET", "/v1/sandboxes/{sandbox_id}/metrics"): "resource metrics not yet public on Cloud",
    ("GET", "/v1/billing"): "billing account state is dashboard-facing",
    ("GET", "/v1/billing/invoices"): "invoice flows are dashboard-facing",
    ("GET", "/v1/billing/invoices/{invoice_id}"): "invoice flows are dashboard-facing",
    ("GET", "/v1/billing/plans"): "plan selection is dashboard-facing",
}

# Every operation expected in the public reference; the script fails if one
# disappears from the live spec so removals are always a conscious decision.
EXPECTED = {
    ("GET", "/v1/sandboxes"),
    ("POST", "/v1/sandboxes"),
    ("GET", "/v1/sandboxes/{sandbox_id}"),
    ("PATCH", "/v1/sandboxes/{sandbox_id}"),
    ("DELETE", "/v1/sandboxes/{sandbox_id}"),
    ("POST", "/v1/sandboxes/{sandbox_id}/start"),
    ("POST", "/v1/sandboxes/{sandbox_id}/stop"),
    ("GET", "/v1/sandboxes/by-name/{name}"),
    ("DELETE", "/v1/sandboxes/by-name/{name}"),
    ("POST", "/v1/sandboxes/by-name/{name}/start"),
    ("POST", "/v1/sandboxes/by-name/{name}/stop"),
    ("GET", "/v1/volumes"),
    ("POST", "/v1/volumes"),
    ("PATCH", "/v1/volumes/{id}"),
    ("DELETE", "/v1/volumes/{id}"),
    ("GET", "/v1/events"),
    ("GET", "/v1/events/{event_id}"),
    ("GET", "/v1/me/org"),
    ("GET", "/v1/members"),
    ("GET", "/v1/quotas"),
    ("GET", "/v1/billing/usage"),
    ("GET", "/v1/billing/usage/sandbox"),
    ("GET", "/v1/billing/usage/storage"),
}

SUMMARY_PREFIX = re.compile(r"^(GET|POST|PUT|PATCH|DELETE)\s+\S+\s+[—–-]+\s+", re.IGNORECASE)
PAREN_NOISE = re.compile(r"\s*\((API key[^)]*|Member\+|Admin\+|Owner only)\)")

# Sidebar group per upstream tag, in display order. Mintlify renders tag names
# verbatim as nav groups, so raw tags like `audit-log` are retitled here.
TAG_GROUPS = {
    "sandboxes": "Sandboxes",
    "volumes": "Volumes",
    "quotas": "Quotas",
    "billing": "Usage",
    "audit-log": "Audit events",
    "organizations": "Organization",
    "members": "Members",
}

# Schemas referenced by operations but missing from the live spec's components
# (upstream utoipa registration gaps). Injected here so the published spec has
# no dangling $refs; remove entries once the upstream spec registers them.
INJECTED_SCHEMAS = {
    "SandboxWaitFor": {
        "type": "string",
        "enum": ["running"],
        "description": "Lifecycle state an opt-in create request may wait to observe.",
    },
    # The live spec types the create-request rootfs source as a bare object;
    # the hosted cloud accepts OCI images only, so publish that shape.
    "CloudRootfsSource": {
        "type": "object",
        "description": "Root filesystem source. The hosted cloud accepts OCI images only.",
        "required": ["type", "reference"],
        "properties": {
            "type": {"type": "string", "enum": ["oci"]},
            "reference": {
                "type": "string",
                "description": "OCI image reference, e.g. `python:3.12`.",
            },
        },
    },
    # Error responses in the live spec carry no body schema; every non-2xx
    # response returns this envelope (verified against the live API).
    "ErrorResponse": {
        "type": "object",
        "description": "Error envelope returned by every non-2xx response.",
        "required": ["error"],
        "properties": {
            "error": {
                "type": "object",
                "required": ["code", "message"],
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Stable machine-readable error code, e.g. `invalid_api_key`.",
                    },
                    "message": {
                        "type": "string",
                        "description": "Human-readable description of the error.",
                    },
                    "details": {
                        "type": ["object", "null"],
                        "description": "Optional structured context for the error.",
                    },
                },
            },
        },
    },
    # utoipa collapses the generic PaginatedResponse<T> into one shared schema
    # whose items ended up typed as org members. Publish a concrete pagination
    # schema per list endpoint instead.
    "PaginatedSandboxResponse": {
        "type": "object",
        "description": "Paginated list of sandboxes.",
        "required": ["data", "has_more"],
        "properties": {
            "data": {"type": "array", "items": {"$ref": "#/components/schemas/SandboxResponse"}},
            "has_more": {"type": "boolean"},
            "next_cursor": {"type": ["string", "null"]},
        },
    },
    "PaginatedMemberResponse": {
        "type": "object",
        "description": "Paginated list of organization members.",
        "required": ["data", "has_more"],
        "properties": {
            "data": {"type": "array", "items": {"$ref": "#/components/schemas/OrgMemberResponse"}},
            "has_more": {"type": "boolean"},
            "next_cursor": {"type": ["string", "null"]},
        },
    },
}

def error_example(status: str, description: str) -> dict | None:
    """Representative error envelope for a response, using real ErrorCode values.

    409 (and other conflict-style) codes differ per endpoint, so the example is
    chosen from the operation's response description rather than the status
    alone. Unrecognized 409 descriptions fail the sync so a new conflict shape
    never ships with a wrong example.
    """
    d = (description or "").lower()
    if "state transition" in d:
        code, msg = "invalid_state_transition", "invalid state transition"
    elif "cannot be deleted" in d:
        code, msg = "invalid_request", "the host volume cannot be deleted"
    elif "cannot be capped" in d:
        code, msg = "invalid_request", "the host volume cannot be capped"
    elif "already" in d:
        code, msg = "name_already_exists", "'name' already exists"
    elif "org not found" in d:
        code, msg = "org_not_found", "org not found"
    elif status == "409":
        sys.exit(f"error: unrecognized 409 description {description!r}; add an example rule")
    elif status == "404":
        code, msg = "sandbox_not_found", "resource not found"
    elif status == "400":
        code, msg = "invalid_request", "invalid request"
    elif status == "401":
        code, msg = "invalid_api_key", "unauthorized"
    elif status == "429":
        code, msg = "rate_limited", "too many requests"
    elif status == "502":
        code, msg = "orchestrator_unreachable", "orchestrator unreachable"
    else:
        return None
    return {"error": {"code": code, "message": msg, "details": None}}

# 200-response schema overrides for operations whose upstream response type is
# the collapsed generic PaginatedResponse.
RESPONSE_OVERRIDES = {
    ("GET", "/v1/sandboxes"): "PaginatedSandboxResponse",
    ("GET", "/v1/members"): "PaginatedMemberResponse",
}

# Reader-facing titles for operations whose upstream summaries carry internal
# phrasing the mechanical cleanup can't fix.
SUMMARY_OVERRIDES = {
    ("GET", "/v1/events"): "List audit events",
    ("GET", "/v1/events/{event_id}"): "Get an audit event",
    ("GET", "/v1/billing/usage"): "Get a usage summary",
    ("GET", "/v1/billing/usage/sandbox"): "Get per-sandbox usage",
    ("GET", "/v1/billing/usage/storage"): "Get per-volume storage usage",
    ("GET", "/v1/me/org"): "Get the current organization",
    ("GET", "/v1/members"): "List organization members",
    ("GET", "/v1/quotas"): "Get quota usage",
}


def clean_summary(summary: str) -> str:
    """Strip the method-and-path prefix and role parentheticals upstream summaries carry."""
    s = " ".join(summary.split())
    s = SUMMARY_PREFIX.sub("", s)
    s = PAREN_NOISE.sub("", s)
    s = s.rstrip(" .")
    return s[:1].upper() + s[1:] if s else s


def op_uses_api_key(op: dict) -> bool:
    # Public endpoints (auth, health, waitlist) declare no op-level security and
    # fall back to the spec default; only explicit api_key ops are in scope.
    return any("api_key" in requirement for requirement in op.get("security", []))


def collect_refs(node, refs: set):
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            refs.add(ref.rsplit("/", 1)[1])
        for value in node.values():
            collect_refs(value, refs)
    elif isinstance(node, list):
        for value in node:
            collect_refs(value, refs)


def curate(spec: dict) -> dict:
    paths = {}
    seen = set()
    for path, ops in spec["paths"].items():
        kept = {}
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            key = (method.upper(), path)
            if op.get("x-hidden") or key in POLICY_EXCLUDE:
                continue
            if not op_uses_api_key(op):
                continue
            op = dict(op)
            if key in SUMMARY_OVERRIDES:
                op["summary"] = SUMMARY_OVERRIDES[key]
            elif "summary" in op:
                op["summary"] = clean_summary(op["summary"])
            op["security"] = [{"api_key": []}]
            tags = [t for t in op.get("tags", []) if t in TAG_GROUPS]
            if not tags:
                sys.exit(f"error: {method.upper()} {path} has no tag in TAG_GROUPS")
            op["tags"] = [TAG_GROUPS[tags[0]]]
            if key in RESPONSE_OVERRIDES:
                ok = op["responses"]["200"]["content"]["application/json"]
                ok["schema"] = {"$ref": f"#/components/schemas/{RESPONSE_OVERRIDES[key]}"}
            for status, resp in op["responses"].items():
                if not status.startswith("2") and "content" not in resp:
                    body = {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}
                    example = error_example(status, resp.get("description", ""))
                    if example is not None:
                        body["example"] = example
                    resp["content"] = {"application/json": body}
            kept[method] = op
            seen.add(key)
        if kept:
            paths[path] = kept

    # The shared generic must never leak into the published contract: its item
    # type is whichever instantiation utoipa registered, not the endpoint's.
    leaked = json.dumps(paths).count('#/components/schemas/PaginatedResponse"')
    if leaked:
        sys.exit(
            "error: an operation still references the collapsed PaginatedResponse "
            "schema; add it to RESPONSE_OVERRIDES with its real item type"
        )

    # Order paths by display-group order so the sidebar leads with Sandboxes.
    group_rank = {name: i for i, name in enumerate(TAG_GROUPS.values())}
    paths = dict(
        sorted(
            paths.items(),
            key=lambda kv: (min(group_rank[op["tags"][0]] for op in kv[1].values()), kv[0]),
        )
    )

    missing = EXPECTED - seen
    if missing:
        listing = ", ".join(f"{m} {p}" for m, p in sorted(missing))
        sys.exit(f"error: expected operations missing from the live spec: {listing}")
    unexpected = seen - EXPECTED
    if unexpected:
        listing = ", ".join(f"{m} {p}" for m, p in sorted(unexpected))
        sys.exit(
            "error: new api_key operations appeared in the live spec; review and add "
            f"them to EXPECTED or POLICY_EXCLUDE: {listing}"
        )

    # Close over every schema transitively referenced by the kept operations.
    refs: set = set()
    collect_refs(paths, refs)
    schemas = dict(spec.get("components", {}).get("schemas", {}))
    schemas.update(INJECTED_SCHEMAS)
    while True:
        extra: set = set()
        for name in refs:
            if name in schemas:
                collect_refs(schemas[name], extra)
        if extra <= refs:
            break
        refs |= extra

    dangling = sorted(refs - schemas.keys())
    if dangling:
        sys.exit(
            "error: operations reference schemas absent from the live spec: "
            f"{', '.join(dangling)}; register them upstream or add to INJECTED_SCHEMAS"
        )

    # The spec types the create-request rootfs source as a bare object; point
    # it at the injected OCI-only schema until upstream emits a real one.
    if "CloudSandboxSpec" in schemas:
        props = schemas["CloudSandboxSpec"].get("properties", {})
        if "image" in props:
            props["image"] = {"$ref": "#/components/schemas/CloudRootfsSource"}
            refs.add("CloudRootfsSource")

    return {
        "openapi": spec["openapi"],
        "info": {
            "title": "microsandbox cloud API",
            "description": (
                "REST API for microsandbox cloud: sandbox and volume lifecycle, "
                "organization context, quotas, usage, and audit events, authenticated "
                "with an organization API key."
            ),
            "version": spec["info"]["version"],
        },
        "servers": [{"url": "https://api.microsandbox.dev"}],
        "security": [{"api_key": []}],
        "paths": paths,
        "components": {
            "schemas": {name: schemas[name] for name in sorted(refs) if name in schemas},
            "securitySchemes": {
                "api_key": spec["components"]["securitySchemes"]["api_key"],
            },
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", help="path to a local spec instead of the live URL")
    parser.add_argument("--check", action="store_true", help="fail if the output is stale")
    args = parser.parse_args()

    if args.source:
        spec = json.loads(Path(args.source).read_text())
    else:
        with urllib.request.urlopen(LIVE_SPEC_URL) as response:
            spec = json.load(response)

    rendered = json.dumps(curate(spec), indent=2, ensure_ascii=False) + "\n"
    # House style bans em dashes; upstream doc comments still use them, so
    # normalize to plain dashes until the source text is reworded.
    rendered = rendered.replace("—", "-").replace("–", "-")

    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != rendered:
            sys.exit(f"error: {OUTPUT} is stale; run scripts/sync-docs-openapi.py")
        print("api reference spec is up to date")
        return

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered)
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
