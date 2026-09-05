#!/usr/bin/env python3
"""Derive credential-specific API references from the live Cloud OpenAPI spec.

Authenticated operations are grouped automatically by their declared security
scheme: organization API keys or personal access tokens. Unauthenticated,
hidden, and excluded operations are not published. Each generated spec also
rewrites implementation-oriented summaries into reader-facing titles and
prunes unreferenced schemas.

Usage:
  scripts/sync-docs-openapi.py            # rewrite docs/api-reference/openapi.json
  scripts/sync-docs-openapi.py --check    # exit 1 if the checked-in spec is stale
  scripts/sync-docs-openapi.py --environment staging --audience all
  scripts/sync-docs-openapi.py --source /path/to/openapi.json
"""

import argparse
import copy
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ENVIRONMENTS = {
    "production": {
        "source": "https://api.microsandbox.dev/docs/openapi.json",
        "server": "https://api.microsandbox.dev",
    },
    "staging": {
        "source": "https://api.msbx.fyi/docs/openapi.json",
        "server": "https://api.msbx.fyi",
    },
}
AUDIENCES = {
    "organization": {
        "scheme": "api_key",
        "title": "microsandbox cloud API",
        "description": (
            "REST API for microsandbox cloud operations authenticated with an "
            "organization API key."
        ),
        "outputs": {
            "production": "openapi.json",
            "staging": "openapi.staging.json",
        },
    },
    "personal": {
        "scheme": "bearer",
        "title": "Personal token API",
        "description": "User-scoped API for account and organization management.",
        "outputs": {
            "production": "openapi.personal.json",
            "staging": "openapi.personal.staging.json",
        },
    },
}

SUMMARY_PREFIX = re.compile(r"^(GET|POST|PUT|PATCH|DELETE)\s+\S+\s+[—–-]+\s+", re.IGNORECASE)
PAREN_NOISE = re.compile(r"\s*\((API key[^)]*|Member\+|Admin\+|Owner only)\)")

# Sidebar group per upstream tag, in display order. Mintlify renders tag names
# verbatim as nav groups, so raw tags like `audit-log` are retitled here.
TAG_GROUPS = {
    "users": "Account",
    "sandboxes": "Sandboxes",
    "snapshots": "Snapshots",
    "volumes": "Volumes",
    "quotas": "Quotas",
    "billing": "Billing",
    "audit-log": "Audit events",
    "organizations": "Organization",
    "members": "Members",
    "invites": "Invites",
    "oidc-config": "OIDC",
    "registry-credentials": "Registry credentials",
    "api-keys": "Credentials",
    "personal-access-tokens": "Credentials",
}
TAG_ORDER = {
    "organization": [
        "Sandboxes",
        "Snapshots",
        "Volumes",
        "Quotas",
        "Billing",
        "Audit events",
        "Organization",
        "Members",
    ],
    "personal": [
        "Account",
        "Organization",
        "Members",
        "Invites",
        "OIDC",
        "Credentials",
        "Registry credentials",
        "Sandboxes",
        "Snapshots",
        "Volumes",
        "Quotas",
        "Billing",
        "Audit events",
    ],
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
    "PaginatedSnapshotCandidateResponse": {
        "type": "object",
        "description": "Paginated list of sandboxes eligible for snapshots.",
        "required": ["data", "has_more"],
        "properties": {
            "data": {"type": "array", "items": {"$ref": "#/components/schemas/SandboxResponse"}},
            "has_more": {"type": "boolean"},
            "next_cursor": {"type": ["string", "null"]},
        },
    },
    "PaginatedSnapshotOperationResponse": {
        "type": "object",
        "description": "Paginated list of snapshot operations.",
        "required": ["data", "has_more"],
        "properties": {
            "data": {
                "type": "array",
                "items": {"$ref": "#/components/schemas/SnapshotOperationListItem"},
            },
            "has_more": {"type": "boolean"},
            "next_cursor": {"type": ["string", "null"]},
        },
    },
    "PaginatedSnapshotResponse": {
        "type": "object",
        "description": "Paginated list of managed snapshots.",
        "required": ["data", "has_more"],
        "properties": {
            "data": {"type": "array", "items": {"$ref": "#/components/schemas/CloudSnapshot"}},
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
    ("GET", "/v1/sandboxes/snapshot-candidates"): "PaginatedSnapshotCandidateResponse",
    ("GET", "/v1/members"): "PaginatedMemberResponse",
    ("GET", "/v1/snapshot-operations"): "PaginatedSnapshotOperationResponse",
    ("GET", "/v1/snapshots"): "PaginatedSnapshotResponse",
    ("GET", "/v1/orgs/{slug}/members"): "PaginatedMemberResponse",
    ("GET", "/v1/orgs/{slug}/sandboxes"): "PaginatedSandboxResponse",
    (
        "GET",
        "/v1/orgs/{slug}/sandboxes/snapshot-candidates",
    ): "PaginatedSnapshotCandidateResponse",
    (
        "GET",
        "/v1/orgs/{slug}/snapshot-operations",
    ): "PaginatedSnapshotOperationResponse",
    ("GET", "/v1/orgs/{slug}/snapshots"): "PaginatedSnapshotResponse",
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
    ("POST", "/v1/snapshots"): "Create a snapshot",
    ("GET", "/v1/snapshots"): "List snapshots",
    ("GET", "/v1/snapshots/{snapshot_id}"): "Get a snapshot",
    ("GET", "/v1/snapshots/by-name/{name}"): "Get a snapshot by name",
    ("DELETE", "/v1/snapshots/{snapshot_id}"): "Delete a snapshot",
    ("DELETE", "/v1/snapshots/by-name/{name}"): "Delete a snapshot by name",
    ("GET", "/v1/sandboxes/snapshot-candidates"): "List snapshot candidates",
    ("GET", "/v1/snapshot-operations"): "List snapshot operations",
    ("GET", "/v1/snapshot-operations/{operation_id}"): "Get a snapshot operation",
}


def clean_summary(summary: str) -> str:
    """Strip the method-and-path prefix and role parentheticals upstream summaries carry."""
    s = " ".join(summary.split())
    s = SUMMARY_PREFIX.sub("", s)
    s = PAREN_NOISE.sub("", s)
    s = s.rstrip(" .")
    return s[:1].upper() + s[1:] if s else s


def operation_audience(op: dict) -> str | None:
    """Return the single public audience declared for an operation."""
    if op.get("x-hidden") or op.get("x-excluded"):
        return None
    if not op.get("security"):
        return None

    matches = [
        name
        for name, audience in AUDIENCES.items()
        if audience["scheme"]
        and any(audience["scheme"] in requirement for requirement in op["security"])
    ]
    if len(matches) > 1:
        return "ambiguous"
    return matches[0] if matches else None


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


def curate(spec: dict, *, server_url: str, audience_name: str) -> dict:
    audience = AUDIENCES[audience_name]
    scheme = audience["scheme"]
    paths = {}
    for path, ops in spec["paths"].items():
        kept = {}
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            key = (method.upper(), path)
            if operation_audience(op) != audience_name:
                continue
            op = copy.deepcopy(op)
            if key in SUMMARY_OVERRIDES:
                op["summary"] = SUMMARY_OVERRIDES[key]
            elif "summary" in op:
                op["summary"] = clean_summary(op["summary"])
            op["security"] = [{scheme: []}]
            raw_tag = next(iter(op.get("tags", [])), "Other")
            op["tags"] = [TAG_GROUPS.get(raw_tag, raw_tag.replace("-", " ").capitalize())]
            if key in RESPONSE_OVERRIDES:
                ok = op["responses"]["200"]["content"]["application/json"]
                ok["schema"] = {"$ref": f"#/components/schemas/{RESPONSE_OVERRIDES[key]}"}
            for status, resp in op["responses"].items():
                if (
                    audience_name == "organization"
                    and not status.startswith("2")
                    and "content" not in resp
                ):
                    body = {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}
                    example = error_example(status, resp.get("description", ""))
                    if example is not None:
                        body["example"] = example
                    resp["content"] = {"application/json": body}
            kept[method] = op
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

    # Give each credential section a task-oriented story instead of inheriting
    # the upstream route-registration order.
    group_rank = {name: i for i, name in enumerate(TAG_ORDER[audience_name])}
    paths = dict(
        sorted(
            paths.items(),
            key=lambda kv: (
                min(group_rank.get(op["tags"][0], len(group_rank)) for op in kv[1].values()),
                kv[0],
            ),
        )
    )

    # Close over every schema transitively referenced by the kept operations.
    refs: set = set()
    collect_refs(paths, refs)
    schemas = copy.deepcopy(spec.get("components", {}).get("schemas", {}))
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
            "title": audience["title"],
            "description": audience["description"],
            "version": spec["info"]["version"],
        },
        "servers": [{"url": server_url}],
        "security": [{scheme: []}],
        "paths": paths,
        "components": {
            "schemas": {name: schemas[name] for name in sorted(refs) if name in schemas},
            "securitySchemes": {scheme: spec["components"]["securitySchemes"][scheme]},
        },
    }


def validate_partition(spec: dict) -> None:
    """Require every published operation to map to one credential audience."""
    unmapped = []
    ambiguous = []
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            if not isinstance(op, dict) or op.get("x-hidden") or op.get("x-excluded"):
                continue
            if not op.get("security"):
                continue
            audience = operation_audience(op)
            operation = f"{method.upper()} {path}"
            if audience == "ambiguous":
                ambiguous.append(operation)
            elif audience is None:
                unmapped.append(operation)

    if ambiguous:
        sys.exit(
            "error: operations declare more than one public credential scheme: "
            + ", ".join(ambiguous)
        )
    if unmapped:
        sys.exit(
            "error: visible operations do not map to a public audience: "
            + ", ".join(unmapped)
        )


def output_path(environment: str, audience: str) -> Path:
    filename = AUDIENCES[audience]["outputs"][environment]
    return REPO / "docs" / "api-reference" / filename


def render(spec: dict, *, environment: str, audience: str) -> str:
    rendered = json.dumps(
        curate(
            spec,
            server_url=ENVIRONMENTS[environment]["server"],
            audience_name=audience,
        ),
        indent=2,
        ensure_ascii=False,
    ) + "\n"
    # House style bans em dashes; upstream doc comments still use them, so
    # normalize to plain dashes until the source text is reworded.
    return rendered.replace("—", "-").replace("–", "-")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--environment",
        choices=ENVIRONMENTS,
        default="production",
        help="API environment to read from and generate for (default: production)",
    )
    parser.add_argument(
        "--audience",
        choices=[*AUDIENCES, "all"],
        default="organization",
        help="credential audience to generate (default: organization)",
    )
    parser.add_argument("--source", help="local path or HTTPS URL instead of the environment source")
    parser.add_argument("--check", action="store_true", help="fail if the output is stale")
    args = parser.parse_args()

    environment = ENVIRONMENTS[args.environment]
    source = args.source or environment["source"]

    if source.startswith("https://"):
        request = urllib.request.Request(
            source,
            headers={"User-Agent": "microsandbox-docs-openapi-sync/1.0"},
        )
        with urllib.request.urlopen(request) as response:
            spec = json.load(response)
    else:
        spec = json.loads(Path(source).read_text())

    validate_partition(spec)
    audiences = list(AUDIENCES) if args.audience == "all" else [args.audience]

    if args.check:
        stale = [
            output_path(args.environment, audience)
            for audience in audiences
            if not output_path(args.environment, audience).exists()
            or output_path(args.environment, audience).read_text()
            != render(spec, environment=args.environment, audience=audience)
        ]
        if stale:
            command = (
                "scripts/sync-docs-openapi.py"
                f" --environment {args.environment} --audience {args.audience}"
            )
            sys.exit(
                "error: stale API reference specs: "
                + ", ".join(str(path) for path in stale)
                + f"; run {command}"
            )
        print("API reference specs are up to date")
        return

    for audience in audiences:
        output = output_path(args.environment, audience)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render(spec, environment=args.environment, audience=audience))
        print(f"wrote {output}")


if __name__ == "__main__":
    main()
