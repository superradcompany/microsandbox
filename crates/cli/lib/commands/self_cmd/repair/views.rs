//! Compare immutable disk views inside one preview session, then confirm the chosen group.

use microsandbox::MicrosandboxError;
use microsandbox::sandbox::{StoragePreview, StorageRecovery, StorageRecoverySelection};
use microsandbox_runtime::checkpoint::migration::CandidateSummary;
use microsandbox_utils::format::format_bytes;

use super::super::storage_doctor::{disk_label, grouped_views, write_views};
use super::{answer, index, terminal_text};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Action<'a> {
    Select(usize),
    List(usize, &'a str),
    Read(usize, &'a str),
    Compare(&'a str),
    Cancel,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn choose(mut preview: StoragePreview) -> anyhow::Result<Option<StorageRecovery>> {
    // Keep only the small display summaries outside the session. Browsing and final
    // publication both use the same immutable captures owned by the session.
    let candidates = preview.candidates().to_vec();
    let disks = grouped_views(&candidates);
    anyhow::ensure!(
        !disks.is_empty(),
        "there are no complete disk views to preview"
    );
    let mut selected: Vec<_> = disks
        .iter()
        .map(|(_, views)| (views.len() == 1).then_some(0))
        .collect();
    let mut revisit = None;
    loop {
        if let Some(index) = revisit
            .take()
            .or_else(|| selected.iter().position(Option::is_none))
        {
            let (disk, views) = &disks[index];
            let mount = preview.guest_mount(disk).map(str::to_owned);
            write_views(&mut std::io::stdout().lock(), disk, mount.as_deref(), views)?;
            let root = terminal_text(mount.as_deref().unwrap_or("/"));
            println!(
                "Browse with 'ls NUMBER {root}' or 'cat NUMBER /path'. Compare a file in every view with 'compare /path'."
            );
            let Some(chosen) = browse(&mut preview, disk, mount.as_deref(), views).await? else {
                return Ok(None);
            };
            selected[index] = Some(chosen);
            continue;
        }

        println!("\nSelected disk views:");
        for (i, ((role, views), chosen)) in disks.iter().zip(&selected).enumerate() {
            let disk = disk_label(role, preview.guest_mount(role));
            let choice = chosen.expect("every disk has a choice");
            println!(
                "  {}. {disk}: view {} of {}",
                i + 1,
                choice + 1,
                views.len()
            );
        }
        println!(
            "A selected view can omit writes in other branches. The original files will be retained."
        );
        println!("Type 'browse DISK_NUMBER' to inspect or change a disk before applying.");
        let input = answer("Apply these disk views? [y/N] ")?;
        if let Some(number) = input.strip_prefix("browse ") {
            revisit = index(number.trim(), disks.len());
            if revisit.is_none() {
                eprintln!("Choose a disk number from the summary.");
            }
            continue;
        }
        match input.to_ascii_lowercase().as_str() {
            "y" | "yes" => break,
            "" | "n" | "no" | "q" | "cancel" => return Ok(None),
            _ => eprintln!("Enter y to apply, browse DISK_NUMBER, or q to cancel."),
        }
    }
    let selections = disks
        .into_iter()
        .zip(selected)
        .map(|((disk, views), chosen)| StorageRecoverySelection {
            disk_id: disk.into(),
            candidate_id: views[chosen.expect("every disk has a choice")].id.clone(),
        })
        .collect();
    Ok(Some(preview.confirm(selections).await?))
}

async fn browse(
    preview: &mut StoragePreview,
    disk: &str,
    mount: Option<&str>,
    candidates: &[&CandidateSummary],
) -> anyhow::Result<Option<usize>> {
    loop {
        let input = answer("View number, browse command, or q to cancel: ")?;
        let action = match parse(&input, candidates.len()) {
            Ok(action) => action,
            Err(message) => {
                eprintln!("{message}");
                continue;
            }
        };
        match action {
            Action::Cancel => return Ok(None),
            Action::Select(i) => return Ok(Some(i)),
            Action::List(i, path) => {
                let Some(path) = role_path(mount, path) else {
                    continue;
                };
                match preview.list(disk, &candidates[i].id, path).await {
                    Ok(entries) if entries.is_empty() => println!("(empty directory)"),
                    Ok(entries) => {
                        for entry in entries {
                            println!(
                                "  {}  {}  {}",
                                terminal_text(&entry.kind),
                                format_bytes(entry.size),
                                terminal_text(&entry.name)
                            );
                        }
                    }
                    Err(error) => print_read_error(&error),
                }
            }
            Action::Read(i, path) => {
                let Some(path) = role_path(mount, path) else {
                    continue;
                };
                match preview.read(disk, &candidates[i].id, path).await {
                    Ok(bytes) => print_file(&bytes),
                    Err(error) => print_read_error(&error),
                }
            }
            Action::Compare(path) => {
                let Some(path) = role_path(mount, path) else {
                    continue;
                };
                let mut first = None;
                for (i, view) in candidates.iter().enumerate() {
                    println!("View {}:", i + 1);
                    match preview.read(disk, &view.id, path).await {
                        Ok(bytes) => {
                            if let Some((number, value)) = &first {
                                if *value == bytes {
                                    println!("  same file contents as view {number}");
                                } else {
                                    println!("  differs from view {number}");
                                    print_file(&bytes);
                                }
                            } else {
                                print_file(&bytes);
                                first = Some((i + 1, bytes));
                            }
                        }
                        Err(error) => print_read_error(&error),
                    }
                }
            }
        }
    }
}

// Operators use guest paths. The isolated reader expects a path from the selected
// disk's root; a mount must match a whole component, including for nested mounts.
fn role_path<'a>(mount: Option<&str>, path: &'a str) -> Option<&'a str> {
    let mount = mount.unwrap_or("/").trim_end_matches('/');
    if mount.is_empty() {
        return Some(path);
    }
    if path == mount {
        return Some("/");
    }
    if let Some(relative) = path
        .strip_prefix(mount)
        .filter(|rest| rest.starts_with('/'))
    {
        return Some(relative);
    }
    eprintln!(
        "Use a guest path under {} for this disk.",
        terminal_text(mount)
    );
    None
}

fn parse(input: &str, count: usize) -> Result<Action<'_>, &'static str> {
    if input.is_empty() || (input.eq_ignore_ascii_case("cancel") || input.eq_ignore_ascii_case("q"))
    {
        return Ok(Action::Cancel);
    }
    if let Some(i) = index(input, count) {
        return Ok(Action::Select(i));
    }
    let (command, rest) = input
        .split_once(char::is_whitespace)
        .ok_or("Enter a view number, ls, cat, compare, or cancel.")?;
    let rest = rest.trim_start();
    if command == "compare" {
        return Ok(Action::Compare(guest_path(rest)?));
    }
    let (number, path) = rest
        .split_once(char::is_whitespace)
        .ok_or("Use ls NUMBER /path or cat NUMBER /path.")?;
    let number = index(number, count).ok_or("Choose a view number from this disk.")?;
    let path = guest_path(path.trim_start())?;
    match command {
        "ls" => Ok(Action::List(number, path)),
        "cat" => Ok(Action::Read(number, path)),
        _ => Err("Enter a view number, ls, cat, compare, or cancel."),
    }
}

fn guest_path(path: &str) -> Result<&str, &'static str> {
    if path.starts_with('/') {
        Ok(path)
    } else {
        Err("Use an absolute path inside this disk, starting with /.")
    }
}

fn print_file(bytes: &[u8]) {
    // Bound terminal output separately from the SDK's file limit. Escape controls and
    // non-text bytes so a guest file cannot clear the screen or forge the next prompt.
    const DISPLAY_BYTES: usize = 1024;
    let text = bytes
        .iter()
        .take(DISPLAY_BYTES)
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect::<String>();
    println!(
        "  {} bytes: {text}{}",
        bytes.len(),
        if bytes.len() > DISPLAY_BYTES {
            " … (excerpt)"
        } else {
            ""
        }
    );
}

fn print_read_error(error: &MicrosandboxError) {
    if matches!(error, MicrosandboxError::Io(e) if e.kind() == std::io::ErrorKind::NotFound) {
        println!("  path is absent");
    } else {
        eprintln!(
            "  could not inspect this path: {}",
            terminal_text(&error.to_string())
        );
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_for_owned_disks_are_resolved_against_their_guest_mount() {
        assert_eq!(role_path(Some("/"), "/etc/x"), Some("/etc/x"));
        assert_eq!(role_path(Some("/data"), "/data"), Some("/"));
        assert_eq!(role_path(Some("/data"), "/data/db/file"), Some("/db/file"));
        assert_eq!(role_path(Some("/data"), "/database/db/file"), None);
    }

    #[test]
    fn preview_actions_require_an_explicit_view_and_keep_paths_inside_the_disk() {
        assert_eq!(parse("", 2), Ok(Action::Cancel));
        assert_eq!(parse("cancel", 2), Ok(Action::Cancel));
        assert_eq!(parse("q", 2), Ok(Action::Cancel));
        assert_eq!(parse("2", 2), Ok(Action::Select(1)));
        assert_eq!(parse("ls 1 /", 2), Ok(Action::List(0, "/")));
        assert_eq!(parse("cat 2 /my file", 2), Ok(Action::Read(1, "/my file")));
        assert_eq!(
            parse("compare /project/status", 2),
            Ok(Action::Compare("/project/status"))
        );
        for invalid in [
            "0",
            "3",
            "apply",
            "cat 3 /",
            "compare file",
            "ls /etc",
            "cat 2 C:/test",
        ] {
            assert!(parse(invalid, 2).is_err(), "accepted {invalid}");
        }
    }
}
