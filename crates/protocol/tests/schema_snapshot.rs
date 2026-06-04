//! Snapshot of the protocol's versioning surface, frozen per generation.
//!
//! The surface is the part of the wire contract the version gate cares about:
//! the protocol generation, the frame framing constants and flag bits, and
//! every message type with the generation that introduced it. It is generated
//! from the live types and compared against a checked-in `schema/gen-<N>.json`,
//! so it cannot drift, and a generation bump shows up as a reviewable diff.
//!
//! To re-bless after an intended change:
//!
//! ```text
//! UPDATE_PROTOCOL_SCHEMA=1 cargo test -p microsandbox-protocol --test schema_snapshot
//! ```
//!
//! Prior-generation files are frozen inputs — the generator only ever writes
//! the file for the current `PROTOCOL_VERSION`.

use std::{collections::HashSet, fs};

use microsandbox_protocol::{
    codec::MAX_FRAME_SIZE,
    message::{
        FLAG_SESSION_START, FLAG_SHUTDOWN, FLAG_TERMINAL, FRAME_HEADER_SIZE, MessageType,
        PROTOCOL_VERSION,
    },
};
use serde_json::{Value, json};
use strum::IntoEnumIterator;

/// Render the current protocol surface as deterministic, pretty JSON.
fn render_surface() -> String {
    let message_types: Vec<_> = MessageType::iter()
        .map(|t| {
            json!({
                "wire": t.as_str(),
                "introduced_in": t.min_protocol_version(),
            })
        })
        .collect();

    let surface = json!({
        "protocol_version": PROTOCOL_VERSION,
        "frame": {
            "header_size": FRAME_HEADER_SIZE,
            "max_frame_size": MAX_FRAME_SIZE,
            "flag_terminal": FLAG_TERMINAL,
            "flag_session_start": FLAG_SESSION_START,
            "flag_shutdown": FLAG_SHUTDOWN,
        },
        "message_types": message_types,
    });

    let mut rendered = serde_json::to_string_pretty(&surface).expect("surface serializes");
    rendered.push('\n');
    rendered
}

fn snapshot_path() -> String {
    format!(
        "{}/schema/gen-{}.json",
        env!("CARGO_MANIFEST_DIR"),
        PROTOCOL_VERSION
    )
}

#[test]
fn protocol_surface_matches_snapshot() {
    let rendered = render_surface();
    let path = snapshot_path();

    if std::env::var_os("UPDATE_PROTOCOL_SCHEMA").is_some() {
        let dir = format!("{}/schema", env!("CARGO_MANIFEST_DIR"));
        fs::create_dir_all(&dir).expect("create schema dir");
        fs::write(&path, &rendered).expect("write schema snapshot");
        return;
    }

    let existing = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing protocol schema snapshot at {path}; create it with \
             `UPDATE_PROTOCOL_SCHEMA=1 cargo test -p microsandbox-protocol --test schema_snapshot`"
        )
    });

    assert_eq!(
        rendered, existing,
        "the protocol surface changed versus {path}. If this was intended, re-bless with \
         `UPDATE_PROTOCOL_SCHEMA=1 cargo test -p microsandbox-protocol --test schema_snapshot` \
         and review the diff. Message types and flag bits are append-only, and introducing a new \
         message type must bump PROTOCOL_VERSION."
    );
}

#[test]
fn schema_is_append_only_across_generations() {
    // Every frozen prior-generation snapshot must remain a subset of the current
    // surface: a message type, once shipped at a generation, is never removed or
    // re-numbered. This is what makes "newer peers understand everything older
    // peers did" hold.
    let dir = format!("{}/schema", env!("CARGO_MANIFEST_DIR"));
    let current =
        serde_json::from_str::<Value>(&render_surface()).expect("current surface is valid json");
    let current_types = current["message_types"]
        .as_array()
        .expect("message_types array");
    let current_file = format!("gen-{PROTOCOL_VERSION}.json");

    let mut compared = 0;
    for entry in fs::read_dir(&dir).expect("read schema dir") {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if !name.starts_with("gen-") || !name.ends_with(".json") || name == current_file {
            continue;
        }

        let content = fs::read_to_string(format!("{dir}/{name}")).unwrap();
        let prior = serde_json::from_str::<Value>(&content).expect("prior snapshot is valid json");

        for pt in prior["message_types"].as_array().unwrap() {
            let wire = pt["wire"].as_str().unwrap();
            let current_entry = current_types
                .iter()
                .find(|c| c["wire"] == pt["wire"])
                .unwrap_or_else(|| {
                    panic!(
                        "message type '{wire}' from {name} is missing at generation \
                        {PROTOCOL_VERSION}; message types are append-only and must not be removed"
                    )
                });

            assert_eq!(
                current_entry["introduced_in"], pt["introduced_in"],
                "message type '{wire}' changed its introduced_in versus {name}; \
                a generation's surface is immutable once frozen"
            );
        }
        compared += 1;
    }

    assert!(
        compared > 0,
        "no prior-generation schema snapshot found to compare against in {dir}"
    );
}

#[test]
fn every_message_type_is_sendable_to_a_current_peer() {
    for t in MessageType::iter() {
        assert!(
            t.min_protocol_version() <= PROTOCOL_VERSION,
            "{t:?} requires a generation newer than PROTOCOL_VERSION ({PROTOCOL_VERSION})"
        );
    }
}

#[test]
fn message_type_wire_strings_are_unique_and_roundtrip() {
    let mut seen = HashSet::new();
    for t in MessageType::iter() {
        assert!(
            seen.insert(t.as_str()),
            "duplicate wire string {}",
            t.as_str()
        );
        assert_eq!(
            MessageType::from_wire_str(t.as_str()),
            Some(t),
            "wire string for {t:?} does not round-trip"
        );
    }
}
