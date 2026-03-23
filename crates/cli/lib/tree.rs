//! `--tree` flag: displays the complete command hierarchy with descriptions.
//!
//! An alternative to `--help` that shows every command, subcommand, and flag
//! in a single tree view with aligned descriptions and color-coded depth.
//!
//! Must be checked **before** `Cli::parse()` to avoid clap validation errors
//! when required arguments are missing.

use std::fmt::Write;

use clap::Command;
use console::style;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builds a formatted tree view of a clap [`Command`] hierarchy.
pub struct TreeBuilder {
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
            output: String::with_capacity(4096),
            indent_stack: Vec::with_capacity(8),
            max_item_width: 0,
        }
    }

    /// Two-pass build: measure widths, then render.
    fn build(mut self, cmd: &Command, root_label: &str) -> String {
        // Pass 1: compute max item width for column alignment.
        self.measure_widths(cmd, 0);
        self.max_item_width += 2; // padding between item and description

        // Pass 2: render tree.
        writeln!(&mut self.output, "{}", style(root_label).yellow().bold()).unwrap();
        self.render_command(cmd);
        self.output
    }

    // ----- Pass 1: width measurement -----

    /// Recursively measure widths of all visible items.
    fn measure_widths(&mut self, cmd: &Command, depth: usize) {
        let indent = depth * 4; // each level adds "│   " or "    " (4 chars)
        let branch = 4; // "├── " or "└── "

        // Measure args (positionals + flags).
        for arg in cmd.get_arguments() {
            if Self::skip_arg(arg) {
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
        // Collect items in display order: positionals, then flags, then subcommands.
        let mut positionals: Vec<&clap::Arg> = Vec::new();
        let mut flags: Vec<&clap::Arg> = Vec::new();

        for arg in cmd.get_arguments() {
            if Self::skip_arg(arg) {
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
        if let Some(desc) = description.filter(|d| !d.is_empty()) {
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

        if let Some(about) = cmd.get_about() {
            let about_str = about.to_string();
            if let Some(line) = about_str.lines().next().filter(|l| !l.is_empty()) {
                write!(&mut self.output, "{:width$}{}", "", line, width = pad).unwrap();
            }
        }

        writeln!(&mut self.output).unwrap();

        // Recurse if there are visible children.
        let has_children = cmd.get_subcommands().any(|s| !s.is_hide_set())
            || cmd.get_arguments().any(|a| !Self::skip_arg(a));

        if has_children {
            self.indent_stack.push(!is_last);
            self.render_command(cmd);
            self.indent_stack.pop();
        }
    }

    // ----- Helpers -----

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
    fn skip_arg(arg: &clap::Arg) -> bool {
        let id = arg.get_id().as_str();
        id == "help" || id == "version" || id == "tree" || arg.is_hide_set()
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

    if !args.iter().any(|a| a == "--tree") {
        return None;
    }

    let (path, deepest) = find_deepest_subcommand(cmd, &args);

    let tree = if path.len() > 1 {
        generate_tree_with_root(&deepest, &path.join(" "))
    } else {
        generate_tree(&deepest)
    };

    Some(tree)
}

/// Walk `args` to find the deepest subcommand the user specified before `--tree`.
fn find_deepest_subcommand(cmd: &Command, args: &[String]) -> (Vec<String>, Command) {
    let mut path = vec![cmd.get_name().to_string()];
    let mut current = cmd.clone();

    // Skip argv[0] (program name).
    for arg in args.iter().skip(1) {
        // Stop at flags.
        if arg.starts_with('-') {
            continue;
        }

        if let Some(sub) = current.find_subcommand(arg) {
            if sub.is_hide_set() {
                continue;
            }
            path.push(arg.to_string());
            current = sub.clone();
        }
    }

    (path, current)
}
