//! Generate checked TypeScript bindings for microsandbox shared types.

use std::env;
use std::fs;
use std::path::PathBuf;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct Target {
    label: &'static str,
    path: PathBuf,
    content: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn main() {
    let check = env::args().skip(1).any(|arg| arg == "--check");
    let targets = targets();

    if check {
        check_targets(&targets);
    } else {
        write_targets(&targets);
    }
}

fn targets() -> Vec<Target> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let package_root = manifest_dir
        .parent()
        .expect("microsandbox-types rust crate should live under <package>/rust");
    let src = package_root.join("typescript/src");

    vec![
        Target {
            label: "microsandbox-types domain bindings",
            path: src.join("domain.ts"),
            content: microsandbox_types::typescript::render_domain(),
        },
        Target {
            label: "microsandbox-types cloud bindings",
            path: src.join("cloud.ts"),
            content: microsandbox_types::typescript::render_cloud(),
        },
    ]
}

fn check_targets(targets: &[Target]) {
    let mut stale = Vec::new();

    for target in targets {
        let current = fs::read_to_string(&target.path).unwrap_or_default();
        if current != target.content {
            stale.push(target);
        }
    }

    if stale.is_empty() {
        return;
    }

    for target in stale {
        eprintln!("{} is stale: {}", target.label, target.path.display());
    }
    eprintln!(
        "run `cargo run -p microsandbox-types --features ts --bin microsandbox-types-generate` to refresh generated bindings"
    );
    std::process::exit(1);
}

fn write_targets(targets: &[Target]) {
    for target in targets {
        if let Some(parent) = target.path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|err| {
                panic!("failed to create {}: {err}", parent.display());
            });
        }
        fs::write(&target.path, &target.content).unwrap_or_else(|err| {
            panic!("failed to write {}: {err}", target.path.display());
        });
        println!("wrote {}", target.path.display());
    }
}
