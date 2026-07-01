//! Migration: Harmonize persisted sandbox `config` JSON to the adjacently-tagged
//! wire format.
//!
//! The pre-harmonization build serialized several sandbox-spec enums with
//! serde's external/internal tagging and PascalCase/kebab-case variant names.
//! The harmonized `microsandbox-types` contract tags those enums *adjacently*
//! (`{"type":..,"content":..}`) with snake_case variant names, renames
//! `resources.cpus` → `resources.vcpus`, and renames the secrets list key
//! `secrets` → `entries`.
//!
//! `up` rewrites old → new so the harmonized build reads persisted configs;
//! `down` rewrites new → old so `msb self downgrade` restores a config the
//! pre-harmonization build can read. Both walk `serde_json::Value` and are
//! idempotent: a row already in the target shape is left untouched and skipped.
//!
//! Beyond the re-tagged enums, several *plain-string* enums also changed variant
//! casing old ↔ new. The harmonized types read the old casing via
//! `#[serde(alias)]`, so `up` does not strictly need them — but `down` does: a
//! config written by the NEW build carries new-canonical casing, and the old
//! build's enums have no snake alias, so `msb self downgrade` would fail to read
//! them. `down` re-cases these back (and `up` does the forward map for symmetry):
//!   - `pull_policy`         — `PullPolicy`     (PascalCase ↔ snake_case)
//!   - `rlimits[].resource`  — `RlimitResource` (PascalCase ↔ lowercase)
//!
//! Affected paths inside `config` (SandboxConfig flattens SandboxSpec, so spec
//! fields sit at the top level):
//!   - `image`                                  — `RootfsSource`  (external → adjacent)
//!   - `mounts[]`                               — `VolumeMount`   (internal-flat → adjacent)
//!   - `patches[]`                              — `Patch`         (external → adjacent)
//!   - `resources.cpus`                         — field rename → `vcpus`
//!   - `pull_policy`                            — `PullPolicy`    string re-casing
//!   - `rlimits[].resource`                     — `RlimitResource` string re-casing
//!   - `network.policy.rules[].destination`     — `Destination`   (external → adjacent)
//!   - `network.secrets` (key `secrets`→`entries`, `on_violation`, and each
//!     entry's `allowed_hosts[]` + `on_violation`) — `HostPattern` / `ViolationAction`
//!   - the `format` field of any `disk_image` rootfs/mount — `DiskImageFormat`
//!     casing (PascalCase ↔ snake_case)

use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
};
use serde_json::{Map, Value};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

/// Rewrite direction: `Up` = old → new, `Down` = new → old.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    Up,
    Down,
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

// Tag maps as `(new_snake, old_variant)`. `Up` maps old → new, `Down` new → old.

/// `RootfsSource` variant tags (externally tagged, PascalCase in the old shape).
const ROOTFS: &[(&str, &str)] = &[
    ("bind", "Bind"),
    ("oci", "Oci"),
    ("disk_image", "DiskImage"),
];

/// `VolumeMount` variant tags (internally tagged flat, PascalCase in the old shape).
const VOLUME_MOUNT: &[(&str, &str)] = &[
    ("bind", "Bind"),
    ("named", "Named"),
    ("tmpfs", "Tmpfs"),
    ("disk_image", "DiskImage"),
];

/// `Patch` variant tags (externally tagged, PascalCase in the old shape).
const PATCH: &[(&str, &str)] = &[
    ("text", "Text"),
    ("file", "File"),
    ("copy_file", "CopyFile"),
    ("copy_dir", "CopyDir"),
    ("symlink", "Symlink"),
    ("mkdir", "Mkdir"),
    ("remove", "Remove"),
    ("append", "Append"),
];

/// `Destination` variant tags (externally tagged, snake_case in the old shape).
const DESTINATION: &[(&str, &str)] = &[
    ("any", "any"),
    ("cidr", "cidr"),
    ("domain", "domain"),
    ("domain_suffix", "domain_suffix"),
    ("group", "group"),
];

/// `HostPattern` variant tags (externally tagged, single-word — kebab == snake).
const HOST_PATTERN: &[(&str, &str)] =
    &[("exact", "exact"), ("wildcard", "wildcard"), ("any", "any")];

/// `ViolationAction` variant tags (externally tagged, kebab-case in the old shape).
const VIOLATION_ACTION: &[(&str, &str)] = &[
    ("block", "block"),
    ("block_and_log", "block-and-log"),
    ("block_and_terminate", "block-and-terminate"),
    ("passthrough", "passthrough"),
];

/// `DiskImageFormat` values (PascalCase in the old shape).
const DISK_FORMAT: &[(&str, &str)] = &[("qcow2", "Qcow2"), ("raw", "Raw"), ("vmdk", "Vmdk")];

/// `PullPolicy` values (bare string; PascalCase in the old shape).
const PULL_POLICY: &[(&str, &str)] = &[
    ("if_missing", "IfMissing"),
    ("always", "Always"),
    ("never", "Never"),
];

/// `RlimitResource` values (bare string; PascalCase in the old shape, lowercase
/// in the new one — all single-word, so new == the lowercased old variant).
const RLIMIT_RESOURCE: &[(&str, &str)] = &[
    ("cpu", "Cpu"),
    ("fsize", "Fsize"),
    ("data", "Data"),
    ("stack", "Stack"),
    ("core", "Core"),
    ("rss", "Rss"),
    ("nproc", "Nproc"),
    ("nofile", "Nofile"),
    ("memlock", "Memlock"),
    ("as", "As"),
    ("locks", "Locks"),
    ("sigpending", "Sigpending"),
    ("msgqueue", "Msgqueue"),
    ("nice", "Nice"),
    ("rtprio", "Rtprio"),
    ("rttime", "Rttime"),
];

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260701_000001_migrate_sandbox_config_wire"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rewrite_all(manager, Dir::Up).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rewrite_all(manager, Dir::Down).await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: row iteration
//--------------------------------------------------------------------------------------------------

/// Rewrite every `sandbox.config` row in the given direction, skipping rows
/// already in the target shape.
async fn rewrite_all(manager: &SchemaManager<'_>, dir: Dir) -> Result<(), DbErr> {
    let conn = manager.get_connection();
    let rows = conn
        .query_all(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT id, config FROM sandbox".to_owned(),
        ))
        .await?;

    for row in rows {
        let id = row.try_get_by_index::<i32>(0)?;
        let config = row.try_get_by_index::<String>(1)?;
        let Some(updated) = migrate_config(&config, dir)? else {
            continue;
        };

        conn.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "UPDATE sandbox SET config = ? WHERE id = ?",
            [updated.into(), id.into()],
        ))
        .await?;
    }

    Ok(())
}

/// Parse, transform in the given direction, and re-serialize. Returns `None`
/// when the config is already in the target shape (nothing changed).
fn migrate_config(config: &str, dir: Dir) -> Result<Option<String>, DbErr> {
    let mut value = serde_json::from_str::<Value>(config)
        .map_err(|err| DbErr::Custom(format!("parse sandbox config JSON: {err}")))?;

    let before = value.clone();
    apply(&mut value, dir);
    if value == before {
        return Ok(None);
    }

    serde_json::to_string(&value)
        .map(Some)
        .map_err(|err| DbErr::Custom(format!("serialize sandbox config JSON: {err}")))
}

//--------------------------------------------------------------------------------------------------
// Functions: config walk
//--------------------------------------------------------------------------------------------------

/// Apply every enum/field transform to a single parsed config document.
fn apply(config: &mut Value, dir: Dir) {
    // image: RootfsSource. `disk_image` also carries a `format` to re-case;
    // Up reshapes then re-cases, Down re-cases (still adjacent) then reshapes.
    if let Some(image) = config.get_mut("image") {
        match dir {
            Dir::Up => {
                reshape_external(image, ROOTFS, Dir::Up);
                remap_disk_format(image, Dir::Up);
            }
            Dir::Down => {
                remap_disk_format(image, Dir::Down);
                reshape_external(image, ROOTFS, Dir::Down);
            }
        }
    }

    // mounts[]: VolumeMount (internal-flat ↔ adjacent), same `format` handling.
    if let Some(Value::Array(mounts)) = config.get_mut("mounts") {
        for mount in mounts.iter_mut() {
            match dir {
                Dir::Up => {
                    reshape_internal(mount, VOLUME_MOUNT, Dir::Up);
                    remap_disk_format(mount, Dir::Up);
                }
                Dir::Down => {
                    remap_disk_format(mount, Dir::Down);
                    reshape_internal(mount, VOLUME_MOUNT, Dir::Down);
                }
            }
        }
    }

    // patches[]: Patch (external ↔ adjacent).
    if let Some(Value::Array(patches)) = config.get_mut("patches") {
        for patch in patches.iter_mut() {
            reshape_external(patch, PATCH, dir);
        }
    }

    // resources.cpus ↔ resources.vcpus.
    if let Some(resources) = config.get_mut("resources").and_then(Value::as_object_mut) {
        match dir {
            Dir::Up => rename_key(resources, "cpus", "vcpus"),
            Dir::Down => rename_key(resources, "vcpus", "cpus"),
        }
    }

    // pull_policy: bare-string PullPolicy (PascalCase ↔ snake_case).
    if let Some(obj) = config.as_object_mut() {
        remap_string(obj, "pull_policy", PULL_POLICY, dir);
    }

    // rlimits[].resource: bare-string RlimitResource (PascalCase ↔ lowercase).
    if let Some(Value::Array(rlimits)) = config.get_mut("rlimits") {
        for rlimit in rlimits.iter_mut() {
            if let Some(obj) = rlimit.as_object_mut() {
                remap_string(obj, "resource", RLIMIT_RESOURCE, dir);
            }
        }
    }

    // network.policy.rules[].destination and network.secrets.
    if let Some(network) = config.get_mut("network") {
        if let Some(secrets) = network.get_mut("secrets") {
            migrate_secrets(secrets, dir);
        }
        if let Some(Value::Array(rules)) = network
            .get_mut("policy")
            .and_then(|policy| policy.get_mut("rules"))
        {
            for rule in rules.iter_mut() {
                if let Some(dest) = rule.get_mut("destination") {
                    reshape_external(dest, DESTINATION, dir);
                }
            }
        }
    }
}

/// Transform the `network.secrets` subdocument: rename the list key, and
/// reshape the `ViolationAction` and `HostPattern` nodes it carries.
fn migrate_secrets(secrets: &mut Value, dir: Dir) {
    let Some(obj) = secrets.as_object_mut() else {
        return;
    };

    let (from, to) = match dir {
        Dir::Up => ("secrets", "entries"),
        Dir::Down => ("entries", "secrets"),
    };
    rename_key(obj, from, to);

    if let Some(on_violation) = obj.get_mut("on_violation") {
        reshape_violation(on_violation, dir);
    }

    if let Some(Value::Array(entries)) = obj.get_mut(to) {
        for entry in entries.iter_mut() {
            if let Some(Value::Array(hosts)) = entry.get_mut("allowed_hosts") {
                for host in hosts.iter_mut() {
                    reshape_external(host, HOST_PATTERN, dir);
                }
            }
            if let Some(on_violation) = entry.get_mut("on_violation") {
                reshape_violation(on_violation, dir);
            }
        }
    }
}

/// Reshape a `ViolationAction`. Its `Passthrough` variant carries a
/// `Vec<HostPattern>`, which is reshaped while the node is in adjacent form.
fn reshape_violation(node: &mut Value, dir: Dir) {
    match dir {
        Dir::Up => {
            reshape_external(node, VIOLATION_ACTION, Dir::Up);
            reshape_passthrough_hosts(node, Dir::Up);
        }
        Dir::Down => {
            reshape_passthrough_hosts(node, Dir::Down);
            reshape_external(node, VIOLATION_ACTION, Dir::Down);
        }
    }
}

/// Reshape the `HostPattern` list inside an adjacent `passthrough` node.
fn reshape_passthrough_hosts(node: &mut Value, dir: Dir) {
    if node.get("type").and_then(Value::as_str) != Some("passthrough") {
        return;
    }
    if let Some(Value::Array(hosts)) = node.get_mut("content") {
        for host in hosts.iter_mut() {
            reshape_external(host, HOST_PATTERN, dir);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: enum reshapers
//--------------------------------------------------------------------------------------------------

/// Convert an enum node between the old externally-tagged shape and the new
/// adjacently-tagged shape (`{"type":..,"content":..}`). Unit variants are a
/// bare string in the old shape and `{"type":..}` (no content) in the new one.
fn reshape_external(node: &mut Value, map: &[(&str, &str)], dir: Dir) {
    match dir {
        Dir::Up => {
            if node.get("type").is_some() {
                return; // already adjacent
            }
            let new = if let Some(s) = node.as_str() {
                match map_tag(map, s, Dir::Up) {
                    Some(tag) => tagged(tag, None),
                    None => return,
                }
            } else if let Some(obj) = node.as_object() {
                if obj.len() != 1 {
                    return;
                }
                let (key, val) = obj.iter().next().expect("len == 1");
                match map_tag(map, key, Dir::Up) {
                    Some(tag) => tagged(tag, Some(val.clone())),
                    None => return,
                }
            } else {
                return;
            };
            *node = new;
        }
        Dir::Down => {
            let Some(tag) = node.get("type").and_then(Value::as_str) else {
                return; // not adjacent
            };
            let Some(old_tag) = map_tag(map, tag, Dir::Down).map(str::to_owned) else {
                return;
            };
            let new = match node.get("content").cloned() {
                Some(content) => {
                    let mut obj = Map::new();
                    obj.insert(old_tag, content);
                    Value::Object(obj)
                }
                None => Value::String(old_tag),
            };
            *node = new;
        }
    }
}

/// Convert an enum node between the old internally-tagged flat shape
/// (`{"type":"Bind", ...fields}`) and the new adjacent shape.
fn reshape_internal(node: &mut Value, map: &[(&str, &str)], dir: Dir) {
    match dir {
        Dir::Up => {
            if node.get("content").is_some() {
                return; // already adjacent
            }
            let Some(obj) = node.as_object() else {
                return;
            };
            let Some(tag) = obj
                .get("type")
                .and_then(Value::as_str)
                .and_then(|t| map_tag(map, t, Dir::Up))
                .map(str::to_owned)
            else {
                return;
            };
            let mut content = obj.clone();
            content.remove("type");
            let mut wrapper = Map::new();
            wrapper.insert("type".to_owned(), Value::String(tag));
            wrapper.insert("content".to_owned(), Value::Object(content));
            *node = Value::Object(wrapper);
        }
        Dir::Down => {
            let Some(content) = node.get("content").cloned() else {
                return; // already flat
            };
            let Some(old_tag) = node
                .get("type")
                .and_then(Value::as_str)
                .and_then(|t| map_tag(map, t, Dir::Down))
                .map(str::to_owned)
            else {
                return;
            };
            let Value::Object(mut fields) = content else {
                return;
            };
            fields.insert("type".to_owned(), Value::String(old_tag));
            *node = Value::Object(fields);
        }
    }
}

/// Re-case the `format` of an adjacent `disk_image` rootfs/mount node.
fn remap_disk_format(node: &mut Value, dir: Dir) {
    if node.get("type").and_then(Value::as_str) != Some("disk_image") {
        return;
    }
    let Some(content) = node.get_mut("content").and_then(Value::as_object_mut) else {
        return;
    };
    let Some(mapped) = content
        .get("format")
        .and_then(Value::as_str)
        .and_then(|f| map_tag(DISK_FORMAT, f, dir))
        .map(str::to_owned)
    else {
        return;
    };
    content.insert("format".to_owned(), Value::String(mapped));
}

/// Re-case a bare-string enum value at `obj[key]` using `map` in the given
/// direction. Self-detecting and idempotent: absent, non-string, or already
/// target-cased values (no `map_tag` hit) are left untouched.
fn remap_string(obj: &mut Map<String, Value>, key: &str, map: &[(&str, &str)], dir: Dir) {
    let Some(mapped) = obj
        .get(key)
        .and_then(Value::as_str)
        .and_then(|s| map_tag(map, s, dir))
        .map(str::to_owned)
    else {
        return;
    };
    obj.insert(key.to_owned(), Value::String(mapped));
}

//--------------------------------------------------------------------------------------------------
// Functions: helpers
//--------------------------------------------------------------------------------------------------

/// Build an adjacent node `{"type": tag}` or `{"type": tag, "content": ..}`.
fn tagged(tag: &str, content: Option<Value>) -> Value {
    let mut obj = Map::new();
    obj.insert("type".to_owned(), Value::String(tag.to_owned()));
    if let Some(content) = content {
        obj.insert("content".to_owned(), content);
    }
    Value::Object(obj)
}

/// Look up a tag across the direction: `Up` maps old → new, `Down` new → old.
fn map_tag<'a>(map: &'a [(&'a str, &'a str)], key: &str, dir: Dir) -> Option<&'a str> {
    map.iter().find_map(|(new, old)| match dir {
        Dir::Up => (*old == key).then_some(*new),
        Dir::Down => (*new == key).then_some(*old),
    })
}

/// Rename an object key in place, preserving the value. No-op if absent.
fn rename_key(obj: &mut Map<String, Value>, from: &str, to: &str) {
    if let Some(value) = obj.remove(from) {
        obj.insert(to.to_owned(), value);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_types::SandboxSpec;

    /// A representative OLD (pre-harmonization) `config` document exercising
    /// every migrated enum in its old serialized shape.
    fn old_config() -> &'static str {
        r#"{
          "name": "demo",
          "image": { "Oci": { "reference": "python", "upper_size_mib": 4096 } },
          "resources": { "cpus": 2, "memory_mib": 1024 },
          "pull_policy": "IfMissing",
          "rlimits": [
            { "resource": "Nofile", "soft": 1024, "hard": 4096 },
            { "resource": "As", "soft": 0, "hard": 0 }
          ],
          "mounts": [
            { "type": "Bind", "host": "/host/data", "guest": "/data",
              "options": {"readonly":false,"noexec":false,"nosuid":false,"nodev":false},
              "stat_virtualization": "strict", "host_permissions": "private", "quota_mib": null },
            { "type": "DiskImage", "host": "/host/disk.ext4", "guest": "/mnt/disk",
              "format": "Raw", "fstype": null,
              "options": {"readonly":false,"noexec":false,"nosuid":false,"nodev":false} },
            { "type": "Tmpfs", "guest": "/tmp/scratch", "size_mib": 64,
              "options": {"readonly":false,"noexec":false,"nosuid":false,"nodev":false} },
            { "type": "Named", "name": "cache", "guest": "/var/cache",
              "options": {"readonly":false,"noexec":false,"nosuid":false,"nodev":false},
              "stat_virtualization": "strict", "host_permissions": "private" }
          ],
          "patches": [
            { "Text": { "path": "/etc/app.conf", "content": "debug=true", "mode": 420, "replace": true } },
            { "File": { "path": "/etc/raw", "content": [104,105], "mode": null, "replace": false } },
            { "CopyFile": { "src": "/host/f", "dst": "/etc/f", "mode": null, "replace": false } },
            { "CopyDir": { "src": "/host/d", "dst": "/etc/d", "replace": false } },
            { "Symlink": { "target": "/bin/busybox", "link": "/usr/bin/ls", "replace": false } },
            { "Mkdir": { "path": "/opt/app", "mode": 493 } },
            { "Remove": { "path": "/tmp/junk" } },
            { "Append": { "path": "/etc/hosts", "content": "1.2.3.4 host" } }
          ],
          "network": {
            "policy": {
              "default_egress": "deny",
              "default_ingress": "deny",
              "rules": [
                { "direction": "egress", "destination": "any", "protocols": [], "ports": [], "action": "allow" },
                { "direction": "egress", "destination": {"cidr": "10.0.0.0/8"}, "protocols": ["tcp"], "ports": [], "action": "deny" },
                { "direction": "egress", "destination": {"domain": "example.com"}, "protocols": [], "ports": [], "action": "allow" },
                { "direction": "egress", "destination": {"domain_suffix": "internal.corp"}, "protocols": [], "ports": [], "action": "allow" },
                { "direction": "ingress", "destination": {"group": "loopback"}, "protocols": [], "ports": [], "action": "allow" }
              ]
            },
            "secrets": {
              "secrets": [
                { "env_var": "API_KEY", "value": "sk-secret", "placeholder": "$MSB_API_KEY",
                  "allowed_hosts": [ {"exact": "api.example.com"}, {"wildcard": "*.example.com"}, "any" ],
                  "injection": {"headers":true,"basic_auth":true,"query_params":false,"body":false},
                  "on_violation": "block-and-log",
                  "require_tls_identity": true }
              ],
              "on_violation": { "passthrough": [ {"exact": "logs.example.com"}, "any" ] }
            }
          },
          "manifest_digest": "sha256:abc123"
        }"#
    }

    #[test]
    fn up_produces_the_new_wire_shape() {
        let up = migrate_config(old_config(), Dir::Up).unwrap().unwrap();
        let v: Value = serde_json::from_str(&up).unwrap();

        // image: RootfsSource — adjacent.
        assert_eq!(v["image"]["type"], "oci");
        assert_eq!(v["image"]["content"]["reference"], "python");

        // resources: cpus → vcpus.
        assert_eq!(v["resources"]["vcpus"], 2);
        assert!(v["resources"].get("cpus").is_none());

        // pull_policy + rlimits: bare-string enums re-cased old → new.
        assert_eq!(v["pull_policy"], "if_missing");
        assert_eq!(v["rlimits"][0]["resource"], "nofile");
        assert_eq!(v["rlimits"][1]["resource"], "as");

        // mounts: VolumeMount — adjacent, disk_image format re-cased.
        assert_eq!(v["mounts"][0]["type"], "bind");
        assert_eq!(v["mounts"][0]["content"]["host"], "/host/data");
        assert_eq!(v["mounts"][1]["type"], "disk_image");
        assert_eq!(v["mounts"][1]["content"]["format"], "raw");
        assert_eq!(v["mounts"][3]["type"], "named");

        // patches: Patch — adjacent, snake_case multiword tags.
        assert_eq!(v["patches"][0]["type"], "text");
        assert_eq!(v["patches"][2]["type"], "copy_file");
        assert_eq!(v["patches"][3]["type"], "copy_dir");
        assert_eq!(v["patches"][6]["type"], "remove");

        // policy: Destination — adjacent.
        let rules = &v["network"]["policy"]["rules"];
        assert_eq!(rules[0]["destination"]["type"], "any");
        assert_eq!(rules[1]["destination"]["type"], "cidr");
        assert_eq!(rules[1]["destination"]["content"], "10.0.0.0/8");
        assert_eq!(rules[3]["destination"]["type"], "domain_suffix");
        assert_eq!(rules[4]["destination"]["content"], "loopback");

        // secrets: list key renamed, HostPattern + ViolationAction reshaped.
        let secrets = &v["network"]["secrets"];
        assert!(secrets.get("secrets").is_none());
        let entry = &secrets["entries"][0];
        assert_eq!(entry["allowed_hosts"][0]["type"], "exact");
        assert_eq!(entry["allowed_hosts"][2]["type"], "any");
        assert_eq!(entry["on_violation"]["type"], "block_and_log");
        assert_eq!(secrets["on_violation"]["type"], "passthrough");
        assert_eq!(secrets["on_violation"]["content"][0]["type"], "exact");
        assert_eq!(secrets["on_violation"]["content"][1]["type"], "any");
    }

    #[test]
    fn up_output_deserializes_as_current_sandbox_spec() {
        let up = migrate_config(old_config(), Dir::Up).unwrap().unwrap();
        let spec: SandboxSpec = serde_json::from_str(&up)
            .expect("migrated config must deserialize as the current SandboxSpec");
        assert_eq!(spec.resources.vcpus, 2);
        assert_eq!(spec.mounts.len(), 4);
        assert_eq!(spec.patches.len(), 8);
        assert_eq!(spec.rlimits.len(), 2);
    }

    #[test]
    fn round_trip_up_then_down_restores_the_old_shape() {
        let original: Value = serde_json::from_str(old_config()).unwrap();

        let up = migrate_config(old_config(), Dir::Up).unwrap().unwrap();
        let down = migrate_config(&up, Dir::Down).unwrap().unwrap();
        let restored: Value = serde_json::from_str(&down).unwrap();

        assert_eq!(
            restored, original,
            "down(up(old)) must equal the old config"
        );
    }

    #[test]
    fn migrations_are_idempotent() {
        // up is a no-op on an already-new config; down is a no-op on an old one.
        let up = migrate_config(old_config(), Dir::Up).unwrap().unwrap();
        assert!(migrate_config(&up, Dir::Up).unwrap().is_none());
        assert!(migrate_config(old_config(), Dir::Down).unwrap().is_none());

        let down = migrate_config(&up, Dir::Down).unwrap().unwrap();
        assert!(migrate_config(&down, Dir::Down).unwrap().is_none());
    }

    /// A config written by the NEW build carries new-canonical casing for the
    /// bare-string enums (`pull_policy`, `rlimits[].resource`). The old build's
    /// enums have no snake alias, so `down` must re-case them back or
    /// `msb self downgrade` can't read the row. Assert none of these fields
    /// still carry new-only casing after `down`.
    #[test]
    fn down_recases_new_only_bare_string_enums_for_the_old_build() {
        let new_native = r#"{
          "name": "demo",
          "image": { "type": "oci", "content": { "reference": "python" } },
          "resources": { "vcpus": 2, "memory_mib": 1024 },
          "pull_policy": "always",
          "rlimits": [
            { "resource": "nofile", "soft": 1024, "hard": 4096 },
            { "resource": "as", "soft": 0, "hard": 0 },
            { "resource": "sigpending", "soft": 1, "hard": 1 }
          ]
        }"#;

        let down = migrate_config(new_native, Dir::Down).unwrap().unwrap();
        let v: Value = serde_json::from_str(&down).unwrap();

        // The old build reads these back in its PascalCase form.
        assert_eq!(v["pull_policy"], "Always");
        assert_eq!(v["rlimits"][0]["resource"], "Nofile");
        assert_eq!(v["rlimits"][1]["resource"], "As");
        assert_eq!(v["rlimits"][2]["resource"], "Sigpending");

        // No new-canonical casing must survive the downgrade.
        assert_ne!(v["pull_policy"], "always");
        let resources: Vec<&str> = v["rlimits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["resource"].as_str().unwrap())
            .collect();
        for r in &resources {
            assert!(
                RLIMIT_RESOURCE.iter().any(|(_, old)| old == r),
                "resource {r:?} is not an old-build RlimitResource spelling"
            );
        }
    }
}
