//! `--tree` flag: displays the complete command hierarchy with descriptions.
//!
//! An alternative to `--help` that shows every command, subcommand, and flag
//! in a single tree view with aligned descriptions and color-coded depth.
//!
//! Must be checked **before** `Cli::parse()` to avoid clap validation errors
//! when required arguments are missing.

use std::fmt::Write;

use clap::{Args, Command, FromArgMatches};
use console::style;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options shared by CLI help and the early command-tree parser.
#[derive(Args, Default)]
pub struct TreeArgs {
    /// Print the command tree and exit.
    #[arg(long, global = true)]
    tree: bool,

    /// Limit tree depth (root is level 0; requires --tree).
    #[arg(short = 'L', long, global = true, requires = "tree", value_name = "N")]
    levels: Option<usize>,

    /// Show only commands, hiding flags and arguments (requires --tree).
    #[arg(short = 'C', long, global = true, requires = "tree")]
    commands: bool,

    /// Omit descriptions from the command tree (requires --tree).
    #[arg(short = 'b', long, global = true, requires = "tree")]
    brief: bool,
}

/// Builds a formatted tree view of a clap [`Command`] hierarchy.
pub struct TreeBuilder {
    /// Rendering controls; defaults preserve the complete tree.
    options: TreeArgs,

    /// Accumulated output buffer.
    output: String,

    /// Stack tracking whether each ancestor still has remaining siblings.
    /// `true` means the ancestor has more items after the current branch,
    /// so a `│` continuation line is drawn; `false` means it was the last
    /// item and we draw blank space instead.
    indent_stack: Vec<bool>,

    /// Maximum item width across the entire tree (computed in pass 1)
    /// used to align descriptions into a single column.
    max_item_width: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TreeBuilder {
    /// Create a new builder.
    fn new() -> Self {
        Self {
            options: TreeArgs::default(),
            output: String::with_capacity(4096),
            indent_stack: Vec::with_capacity(8),
            max_item_width: 0,
        }
    }

    /// Two-pass build: measure widths, then render.
    fn build(mut self, cmd: &Command, root_label: &str) -> String {
        // Brief output has no description column, so it needs no width-measurement pass.
        if !self.options.brief {
            self.measure_widths(cmd, 0);
            self.max_item_width += 2; // padding between item and description
        }

        // Pass 2: render tree.
        write!(&mut self.output, "{}", style(root_label).yellow().bold()).unwrap();
        self.render_collapsed_summary(cmd, 0);
        writeln!(&mut self.output).unwrap();
        self.render_command(cmd);
        self.output
    }

    // ----- Pass 1: width measurement -----

    /// Recursively measure widths of all visible items.
    fn measure_widths(&mut self, cmd: &Command, depth: usize) {
        if self.at_depth_limit(depth) {
            return;
        }
        let indent = depth * 4; // each level adds "│   " or "    " (4 chars)
        let branch = 4; // "├── " or "└── "

        // Measure args (positionals + flags).
        for arg in cmd.get_arguments() {
            if self.skip_arg(arg) {
                continue;
            }
            let w = indent + branch + Self::arg_display_width(arg);
            self.max_item_width = self.max_item_width.max(w);
        }

        // Measure visible subcommands.
        for sub in cmd.get_subcommands() {
            if sub.is_hide_set() {
                continue;
            }
            let w = indent + branch + Self::subcommand_display_width(sub);
            self.max_item_width = self.max_item_width.max(w);

            self.measure_widths(sub, depth + 1);
        }
    }

    /// Exact display width of a formatted argument string.
    fn arg_display_width(arg: &clap::Arg) -> usize {
        let id = arg.get_id().as_str();

        // Positional argument: <NAME> or [NAME]
        if arg.get_short().is_none() && arg.get_long().is_none() {
            let name = arg
                .get_value_names()
                .and_then(|v| v.first().map(|n| n.as_str()))
                .unwrap_or(id);

            // Check for last(true) style: [-- VALUES...]
            if arg.is_last_set() {
                return "[-- ".len() + name.to_uppercase().len() + "...]".len();
            }

            return name.to_uppercase().len() + 2; // <> or []
        }

        let mut w = 0usize;

        // Short flag: -x
        if let Some(_short) = arg.get_short() {
            w += 2; // "-x"
            if arg.get_long().is_some() {
                w += 2; // ", "
            }
        }

        // Long flag: --name
        if let Some(long) = arg.get_long() {
            w += 2 + long.len(); // "--name"
        }

        // Value placeholder: <VALUE>
        if arg.get_num_args().is_some() || arg.get_action().takes_values() {
            if let Some(names) = arg.get_value_names() {
                if let Some(name) = names.first() {
                    w += 1 + name.to_uppercase().len() + 2; // " <NAME>"
                }
            } else {
                w += " <VALUE>".len();
            }
        }

        // Visible aliases: (aliases: --ref, -R)
        let short_aliases: Vec<_> = arg.get_visible_short_aliases().unwrap_or_default();
        let long_aliases: Vec<_> = arg.get_visible_aliases().unwrap_or_default();
        if !short_aliases.is_empty() || !long_aliases.is_empty() {
            w += " (aliases: ".len();
            let mut first = true;
            for _ in &short_aliases {
                if !first {
                    w += 2;
                } // ", "
                w += 2; // "-x"
                first = false;
            }
            for a in &long_aliases {
                if !first {
                    w += 2;
                }
                w += 2 + a.len(); // "--name"
                first = false;
            }
            w += 1; // ")"
        }

        w
    }

    /// Exact display width of a subcommand label (name + aliases).
    fn subcommand_display_width(cmd: &Command) -> usize {
        let mut w = cmd.get_name().len();

        let aliases: Vec<_> = cmd.get_visible_aliases().collect();
        if !aliases.is_empty() {
            // " (aliases: a, b)"
            w += " (aliases: ".len();
            w += aliases.iter().map(|a| a.len()).sum::<usize>();
            w += (aliases.len() - 1) * 2; // ", " separators
            w += 1; // ")"
        }

        w
    }

    // ----- Pass 2: rendering -----

    /// Render all visible items of a command (positionals, flags, subcommands).
    fn render_command(&mut self, cmd: &Command) {
        if self.at_depth_limit(self.indent_stack.len()) {
            return;
        }
        // Collect items in display order: positionals, then flags, then subcommands.
        let mut positionals: Vec<&clap::Arg> = Vec::new();
        let mut flags: Vec<&clap::Arg> = Vec::new();

        for arg in cmd.get_arguments() {
            if self.skip_arg(arg) {
                continue;
            }
            if arg.get_short().is_none() && arg.get_long().is_none() {
                positionals.push(arg);
            } else {
                flags.push(arg);
            }
        }

        let subcommands: Vec<&Command> =
            cmd.get_subcommands().filter(|s| !s.is_hide_set()).collect();

        let total = positionals.len() + flags.len() + subcommands.len();
        let mut idx = 0;

        for arg in &positionals {
            idx += 1;
            self.render_arg(arg, idx == total);
        }

        for arg in &flags {
            idx += 1;
            self.render_arg(arg, idx == total);
        }

        for sub in &subcommands {
            idx += 1;
            self.render_subcommand(sub, idx == total);
        }
    }

    /// Render a single argument (positional or flag).
    fn render_arg(&mut self, arg: &clap::Arg, is_last: bool) {
        let label = Self::format_arg(arg);
        let description = arg.get_help().map(|h| {
            let s = h.to_string();
            s.lines().next().unwrap_or("").to_string()
        });

        let prefix = self.build_prefix(is_last);
        let styled_label = Self::style_arg(&label);

        let current_indent = self.indent_stack.len() * 4;
        let total_width = current_indent + 4 + label.len(); // 4 = branch chars
        let pad = self.max_item_width.saturating_sub(total_width);

        write!(&mut self.output, "{}{}", style(&prefix).dim(), styled_label).unwrap();
        if !self.options.brief
            && let Some(desc) = description.filter(|d| !d.is_empty())
        {
            write!(&mut self.output, "{:width$}{}", "", desc, width = pad).unwrap();
        }
        writeln!(&mut self.output).unwrap();
    }

    /// Render a subcommand header and recurse into its children.
    fn render_subcommand(&mut self, cmd: &Command, is_last: bool) {
        let name = cmd.get_name();
        let aliases: Vec<_> = cmd.get_visible_aliases().collect();

        // Build display label for width calculation.
        let label_width = Self::subcommand_display_width(cmd);
        let current_indent = self.indent_stack.len() * 4;
        let total_width = current_indent + 4 + label_width;
        let pad = self.max_item_width.saturating_sub(total_width);

        let prefix = self.build_prefix(is_last);

        // Color subcommands by depth.
        let colored_name = match self.indent_stack.len() {
            0 => style(name).magenta().bold().to_string(),
            1 => style(name).blue().bold().to_string(),
            2 => style(name).green().bold().to_string(),
            _ => style(name).cyan().bold().to_string(),
        };

        write!(&mut self.output, "{}{}", style(&prefix).dim(), colored_name).unwrap();

        if !aliases.is_empty() {
            write!(
                &mut self.output,
                " {}",
                style(format!("(aliases: {})", aliases.join(", "))).dim()
            )
            .unwrap();
        }

        if !self.options.brief
            && let Some(about) = cmd.get_about()
        {
            let about_str = about.to_string();
            if let Some(line) = about_str.lines().next().filter(|l| !l.is_empty()) {
                write!(&mut self.output, "{:width$}{}", "", line, width = pad).unwrap();
            }
        }

        // Keep the marker on the command's line so the limit bounds actual tree levels.
        self.render_collapsed_summary(cmd, self.indent_stack.len() + 1);
        writeln!(&mut self.output).unwrap();

        self.indent_stack.push(!is_last);
        self.render_command(cmd);
        self.indent_stack.pop();
    }

    // ----- Helpers -----

    /// Whether children of this command fall beyond the requested depth.
    fn at_depth_limit(&self, depth: usize) -> bool {
        self.options.levels.is_some_and(|limit| depth >= limit)
    }

    /// Append a collapse marker only when needed, preserving unbounded output including ANSI codes.
    fn render_collapsed_summary(&mut self, cmd: &Command, depth: usize) {
        let summary = self.collapsed_summary(cmd, depth);
        if !summary.is_empty() {
            write!(&mut self.output, "{}", style(summary).dim()).unwrap();
        }
    }

    /// Count immediate children hidden by depth, respecting visibility and commands-only mode.
    fn collapsed_summary(&self, cmd: &Command, depth: usize) -> String {
        if !self.at_depth_limit(depth) {
            return String::new();
        }

        let commands = cmd.get_subcommands().filter(|s| !s.is_hide_set()).count();
        let arguments = cmd.get_arguments().filter(|a| !self.skip_arg(a)).count();
        let mut counts = Vec::new();
        for (count, noun) in [(commands, "subcommand"), (arguments, "argument")] {
            if count > 0 {
                counts.push(format!(
                    "{count} {noun}{}",
                    if count == 1 { "" } else { "s" }
                ));
            }
        }
        if counts.is_empty() {
            String::new()
        } else {
            format!(" … {}", counts.join(", "))
        }
    }

    /// Build the tree prefix string (│/space continuations + ├──/└── branch).
    fn build_prefix(&self, is_last: bool) -> String {
        let depth = self.indent_stack.len();
        let mut prefix = String::with_capacity(depth * 4 + 4);

        for &continues in &self.indent_stack {
            if continues {
                prefix.push_str("│   ");
            } else {
                prefix.push_str("    ");
            }
        }

        if is_last {
            prefix.push_str("└── ");
        } else {
            prefix.push_str("├── ");
        }

        prefix
    }

    /// Format an argument into its display string (no ANSI codes).
    fn format_arg(arg: &clap::Arg) -> String {
        let id = arg.get_id().as_str();

        // Positional argument.
        if arg.get_short().is_none() && arg.get_long().is_none() {
            let name = arg
                .get_value_names()
                .and_then(|v| v.first().map(|n| n.as_str()))
                .unwrap_or(id);

            // Trailing args: [-- COMMAND...]
            if arg.is_last_set() {
                return format!("[-- {}...]", name.to_uppercase());
            }

            return if arg.is_required_set() {
                format!("<{}>", name.to_uppercase())
            } else {
                format!("[{}]", name.to_uppercase())
            };
        }

        let mut s = String::with_capacity(32);

        if let Some(short) = arg.get_short() {
            write!(&mut s, "-{}", short).unwrap();
            if arg.get_long().is_some() {
                s.push_str(", ");
            }
        }

        if let Some(long) = arg.get_long() {
            write!(&mut s, "--{}", long).unwrap();
        }

        if arg.get_num_args().is_some() || arg.get_action().takes_values() {
            if let Some(names) = arg.get_value_names() {
                if let Some(name) = names.first() {
                    write!(&mut s, " <{}>", name.to_uppercase()).unwrap();
                }
            } else {
                s.push_str(" <VALUE>");
            }
        }

        // Visible aliases.
        let short_aliases: Vec<_> = arg.get_visible_short_aliases().unwrap_or_default();
        let long_aliases: Vec<_> = arg.get_visible_aliases().unwrap_or_default();
        if !short_aliases.is_empty() || !long_aliases.is_empty() {
            s.push_str(" (aliases: ");
            let mut first = true;
            for a in &short_aliases {
                if !first {
                    s.push_str(", ");
                }
                write!(&mut s, "-{}", a).unwrap();
                first = false;
            }
            for a in &long_aliases {
                if !first {
                    s.push_str(", ");
                }
                write!(&mut s, "--{}", a).unwrap();
                first = false;
            }
            s.push(')');
        }

        s
    }

    /// Apply ANSI styling to an argument label.
    fn style_arg(label: &str) -> String {
        // Flags: dim
        if label.starts_with('-') {
            if let Some((flag_part, alias_part)) = label.split_once(" (aliases: ") {
                // Flag with aliases: dim flag, dimmer aliases.
                let styled_flag = if let Some((fl, val)) = flag_part.split_once(' ') {
                    format!("{} {}", style(fl).dim(), style(val).dim())
                } else {
                    style(flag_part).dim().to_string()
                };
                return format!(
                    "{} {}",
                    styled_flag,
                    style(format!("(aliases: {}", alias_part)).dim()
                );
            }

            if let Some((fl, val)) = label.split_once(' ') {
                return format!("{} {}", style(fl).dim(), style(val).dim());
            }

            return style(label).dim().to_string();
        }

        // Positionals: dim
        if (label.starts_with('<') && label.ends_with('>'))
            || (label.starts_with('[') && label.ends_with(']'))
            || label.starts_with("[-- ")
        {
            return style(label).dim().to_string();
        }

        label.to_string()
    }

    /// Whether to skip an argument in the tree view.
    fn skip_arg(&self, arg: &clap::Arg) -> bool {
        let id = arg.get_id().as_str();
        self.options.commands
            || matches!(
                id,
                "help" | "version" | "tree" | "levels" | "commands" | "brief"
            )
            || arg.is_hide_set()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Generate a tree view of all commands and options with descriptions.
pub fn generate_tree(cmd: &Command) -> String {
    TreeBuilder::new().build(cmd, cmd.get_name())
}

/// Generate a tree view with a custom root label (e.g. "msb image").
pub fn generate_tree_with_root(cmd: &Command, root: &str) -> String {
    TreeBuilder::new().build(cmd, root)
}

/// If `--tree` is present in `std::env::args`, generate the appropriate tree
/// and return it. Must be called **before** `Cli::parse()`.
pub fn try_show_tree(cmd: &Command) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    try_show_tree_from(cmd, &args).unwrap_or_else(|error| error.exit())
}

/// Parse only tree controls so command-specific required arguments remain optional in tree mode.
fn try_show_tree_from(cmd: &Command, args: &[String]) -> Result<Option<String>, clap::Error> {
    // Guest command arguments after `--` must not activate or configure the CLI tree.
    let args = &args[..args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len())];
    if !args.iter().any(|a| a == "--tree") {
        return Ok(None);
    }

    let mut tree_args = vec!["msb"];
    let mut path = vec![cmd.get_name().to_string()];
    let mut current = cmd;
    let mut remaining = args.iter().skip(1);
    while let Some(arg) = remaining.next() {
        // Values of options such as `run --init-arg` can look like tree controls or
        // subcommand names. Consume them before interpreting either kind of token.
        if let Some(name) = arg.strip_prefix("--")
            && current.get_arguments().any(|option| {
                option.get_long() == Some(name) && option.is_allow_hyphen_values_set()
            })
        {
            remaining.next();
            continue;
        }

        match arg.as_str() {
            "-L" | "--levels" => {
                tree_args.push(arg);
                if let Some(value) = remaining.next() {
                    tree_args.push(value);
                }
            }
            "--tree" | "--commands" | "--brief" => tree_args.push(arg),
            _ if arg.starts_with("-C") || arg.starts_with("-b") => {
                tree_args.push(arg);
                // Clap handles short-option clusters. Only a trailing -L needs another token,
                // as in `-CbL 2`; `-CbL2` already carries its own depth value.
                if arg[1..].trim_start_matches(['C', 'b']) == "L"
                    && let Some(value) = remaining.next()
                {
                    tree_args.push(value);
                }
            }
            _ if arg.starts_with("-L")
                || arg.starts_with("--levels=")
                || arg.starts_with("--commands=")
                || arg.starts_with("--brief=") =>
            {
                tree_args.push(arg);
            }
            _ => {
                if let Some(sub) = current.find_subcommand(arg)
                    && !sub.is_hide_set()
                {
                    path.push(arg.clone());
                    current = sub;
                }
            }
        }
    }

    // A --tree token consumed as an option value must not activate tree mode.
    if !tree_args.contains(&"--tree") {
        return Ok(None);
    }

    // Reuse the clap definitions advertised in help, including validation of missing/invalid N.
    let matches = TreeArgs::augment_args(Command::new("msb").disable_help_flag(true))
        .try_get_matches_from(tree_args)?;
    let options = TreeArgs::from_arg_matches(&matches)?;
    let mut builder = TreeBuilder::new();
    builder.options = options;

    Ok(Some(builder.build(current, &path.join(" "))))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn command() -> Command {
        TreeArgs::augment_args(Command::new("msb"))
            .arg(
                clap::Arg::new("debug")
                    .long("debug")
                    .action(clap::ArgAction::SetTrue),
            )
            .subcommand(
                Command::new("image")
                    .visible_alias("img")
                    .about("Manage images")
                    .arg(clap::Arg::new("cache").long("cache"))
                    .subcommand(
                        Command::new("pull")
                            .about("Pull an image")
                            .arg(clap::Arg::new("image").required(true))
                            .arg(clap::Arg::new("very-long-option").long("very-long-option")),
                    )
                    .subcommand(Command::new("secret").hide(true)),
            )
            .subcommand(Command::new("version").about("Show version"))
            .subcommand(Command::new("internal").hide(true))
            .arg(clap::Arg::new("hidden").long("hidden").hide(true))
    }

    fn tree(args: &[&str]) -> Result<Option<String>, clap::Error> {
        let args: Vec<_> = args.iter().map(|arg| arg.to_string()).collect();
        try_show_tree_from(&command(), &args)
            .map(|tree| tree.map(|text| console::strip_ansi_codes(&text).into_owned()))
    }

    #[test]
    fn unlimited_output_preserves_existing_renderer() {
        let actual = tree(&["msb", "--tree"]).unwrap().unwrap();
        // Captured from the original renderer, before adding the tree controls.
        assert_eq!(
            actual,
            "msb\n├── --debug\n├── image (aliases: img)                Manage images\n│   ├── --cache <VALUE>\n│   └── pull                            Pull an image\n│       ├── <IMAGE>\n│       └── --very-long-option <VALUE>\n└── version                             Show version\n"
        );
        assert!(!actual.contains('…'));
        for hidden in [
            "--tree",
            "--levels",
            "--commands",
            "--brief",
            "--hidden",
            "secret",
            "internal",
        ] {
            assert!(!actual.contains(hidden), "unexpected {hidden}: {actual}");
        }
    }

    #[test]
    fn commands_keeps_aliases_descriptions_and_branch_connectors() {
        let actual = tree(&["msb", "--tree", "--commands"]).unwrap().unwrap();
        assert_eq!(
            actual,
            "msb\n├── image (aliases: img)  Manage images\n│   └── pull              Pull an image\n└── version               Show version\n"
        );
    }

    #[test]
    fn brief_omits_command_and_argument_descriptions_without_padding() {
        let cmd = command().mut_arg("debug", |arg| arg.help("Enable debug output"));
        let args = ["msb", "--tree", "--brief"].map(String::from);
        let actual = try_show_tree_from(&cmd, &args).unwrap().unwrap();
        assert_eq!(
            console::strip_ansi_codes(&actual),
            "msb\n├── --debug\n├── image (aliases: img)\n│   ├── --cache <VALUE>\n│   └── pull\n│       ├── <IMAGE>\n│       └── --very-long-option <VALUE>\n└── version\n"
        );
    }

    #[test]
    fn brief_combines_with_depth_commands_and_scoping() {
        assert_eq!(
            tree(&["msb", "--brief", "--tree", "--commands", "-L1"])
                .unwrap()
                .unwrap(),
            "msb\n├── image (aliases: img) … 1 subcommand\n└── version\n"
        );
        assert_eq!(
            tree(&["msb", "img", "--tree", "--brief", "-L0"])
                .unwrap()
                .unwrap(),
            "msb img … 1 subcommand, 1 argument\n"
        );
        // The early tree parser accepts controls on either side of the selected subcommand.
        assert_eq!(
            tree(&["msb", "--brief", "img", "--tree", "-L1"]).unwrap(),
            tree(&["msb", "img", "--tree", "--brief", "-L1"]).unwrap()
        );
    }

    #[test]
    fn short_controls_and_clusters_match_long_forms() {
        let expected = tree(&["msb", "image", "--tree", "--commands", "--brief", "-L1"]).unwrap();
        for args in [
            vec!["msb", "image", "--tree", "-C", "-b", "-L1"],
            vec!["msb", "-Cb", "image", "--tree", "-L1"],
            vec!["msb", "image", "--tree", "-bC", "-L1"],
            vec!["msb", "image", "--tree", "-CbL1"],
            vec!["msb", "-bCL", "1", "image", "--tree"],
        ] {
            assert_eq!(tree(&args).unwrap(), expected, "{args:?}");
        }
        assert_eq!(
            tree(&["msb", "--tree", "-C"]).unwrap(),
            tree(&["msb", "--tree", "--commands"]).unwrap()
        );
        assert_eq!(
            tree(&["msb", "--tree", "-b"]).unwrap(),
            tree(&["msb", "--tree", "--brief"]).unwrap()
        );
        for args in [
            vec!["msb", "--tree", "-CbL"],
            vec!["msb", "--tree", "-CbLbad"],
            vec!["msb", "--tree", "-b=1"],
        ] {
            assert!(tree(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn tree_controls_preserve_command_compaction_flags() {
        let cmd = command().subcommand(
            Command::new("modify").arg(
                clap::Arg::new("compact")
                    .long("compact")
                    .action(clap::ArgAction::SetTrue),
            ),
        );
        // Disk compaction must remain usable without --tree and visible inside a brief tree.
        let matches = cmd
            .clone()
            .try_get_matches_from(["msb", "modify", "--compact"])
            .unwrap();
        assert!(
            matches
                .subcommand_matches("modify")
                .unwrap()
                .get_flag("compact")
        );
        let args = ["msb", "modify", "--tree", "--brief"].map(String::from);
        let actual = try_show_tree_from(&cmd, &args).unwrap().unwrap();
        assert_eq!(
            console::strip_ansi_codes(&actual),
            "msb modify\n└── --compact\n"
        );
    }

    #[test]
    fn limit_bounds_rendering_and_alignment_and_counts_visible_children() {
        let actual = tree(&["msb", "--tree", "-L", "1"]).unwrap().unwrap();
        assert_eq!(
            actual,
            "msb\n├── --debug\n├── image (aliases: img)  Manage images … 1 subcommand, 1 argument\n└── version               Show version\n"
        );
    }

    #[test]
    fn commands_limit_counts_only_commands() {
        let actual = tree(&["msb", "--tree", "--commands", "-L2"])
            .unwrap()
            .unwrap();
        // At level 2, pull has only arguments: nothing is collapsed in commands-only mode.
        assert!(!actual.contains('…'));
        let actual = tree(&["msb", "--tree", "--commands", "-L1"])
            .unwrap()
            .unwrap();
        assert!(actual.contains("Manage images … 1 subcommand\n"));
        assert!(!actual.contains("argument"));
    }

    #[test]
    fn zero_limit_shows_only_root_and_summary() {
        assert_eq!(
            tree(&["msb", "--tree", "--levels=0"]).unwrap().unwrap(),
            "msb … 2 subcommands, 1 argument\n"
        );
        assert_eq!(
            tree(&["msb", "--tree", "-L", "0", "--commands"])
                .unwrap()
                .unwrap(),
            "msb … 2 subcommands\n"
        );
    }

    #[test]
    fn limit_is_relative_to_selected_subcommand_and_supports_aliases() {
        for scope in ["image", "img"] {
            let actual = tree(&["msb", "-L", "1", scope, "--tree"]).unwrap().unwrap();
            assert!(actual.starts_with(&format!("msb {scope}\n")));
            assert!(actual.contains("Pull an image … 2 arguments\n"));
            assert!(!actual.contains("--very-long-option"));
        }
        // Tree inspection must work even though `pull` requires an image argument.
        let actual = tree(&["msb", "image", "pull", "--tree", "-L1"])
            .unwrap()
            .unwrap();
        assert!(actual.contains("<IMAGE>"));
        assert!(!actual.contains('…'));
    }

    #[test]
    fn level_spellings_and_option_positions_are_equivalent() {
        let expected = tree(&["msb", "image", "--tree", "-L", "1"]).unwrap();
        for args in [
            vec!["msb", "--tree", "image", "-L1"],
            vec!["msb", "-L=1", "image", "--tree"],
            vec!["msb", "--levels", "1", "image", "--tree"],
            vec!["msb", "image", "--levels=1", "--tree"],
        ] {
            assert_eq!(tree(&args).unwrap(), expected, "{args:?}");
        }
    }

    #[test]
    fn invalid_or_missing_levels_are_errors() {
        for value in ["", "-1", "1.5", "lots", "184467440737095516160"] {
            let flag = format!("--levels={value}");
            assert!(tree(&["msb", "--tree", &flag]).is_err(), "{value}");
        }
        for args in [
            vec!["msb", "--tree", "-L"],
            vec!["msb", "--tree", "--levels"],
            vec!["msb", "--tree", "-L", "--commands"],
            vec!["msb", "--tree", "--commands=yes"],
            vec!["msb", "--tree", "--brief=yes"],
        ] {
            assert!(tree(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn guest_arguments_do_not_activate_or_configure_tree() {
        assert!(
            tree(&["msb", "image", "--", "--tree", "-L0"])
                .unwrap()
                .is_none()
        );
        assert_eq!(
            tree(&["msb", "image", "--tree", "--", "pull", "-L0"]).unwrap(),
            tree(&["msb", "image", "--tree"]).unwrap()
        );
    }

    #[test]
    fn hyphen_values_do_not_configure_tree_or_select_subcommands() {
        let cmd = TreeArgs::augment_args(Command::new("msb")).subcommand(
            Command::new("run")
                .visible_alias("r")
                .arg(
                    clap::Arg::new("init_arg")
                        .long("init-arg")
                        .allow_hyphen_values(true)
                        .action(clap::ArgAction::Append),
                )
                .subcommand(Command::new("child")),
        );
        for scope in ["run", "r"] {
            let baseline = ["msb", scope, "--tree"].map(String::from);
            let expected = try_show_tree_from(&cmd, &baseline).unwrap();
            for value in [
                "-Lfoo",
                "-L2",
                "-C",
                "-b",
                "-CbL2",
                "--levels=0",
                "--commands",
                "--brief",
                "--tree",
                "child",
            ] {
                for args in [
                    vec!["msb", scope, "--tree", "--init-arg", value],
                    vec!["msb", scope, "--init-arg", value, "--tree"],
                ] {
                    let args: Vec<_> = args.into_iter().map(String::from).collect();
                    assert_eq!(
                        try_show_tree_from(&cmd, &args).unwrap(),
                        expected,
                        "{args:?}"
                    );
                }
            }
        }
        let args = ["msb", "run", "--init-arg", "--tree"].map(String::from);
        assert!(try_show_tree_from(&cmd, &args).unwrap().is_none());

        let args = [
            "msb",
            "run",
            "--init-arg",
            "-Lfoo",
            "--init-arg",
            "--brief",
            "--tree",
            "-CbL0",
        ]
        .map(String::from);
        let baseline = ["msb", "run", "--tree", "-CbL0"].map(String::from);
        assert_eq!(
            try_show_tree_from(&cmd, &args).unwrap(),
            try_show_tree_from(&cmd, &baseline).unwrap()
        );
    }
}
